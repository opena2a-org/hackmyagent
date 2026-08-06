/**
 * Security check types and interfaces
 */

import type { Evidence, Rationale, ConceptId } from '../types/finding-evidence';

export type Severity = 'critical' | 'high' | 'medium' | 'low';

/**
 * Project types for filtering relevant checks
 * - cli: Command-line tools (bin field in package.json)
 * - library: NPM packages for use by other code
 * - sdk: API client libraries/SDKs (openai, @anthropic-ai/sdk, etc.)
 * - webapp: Web applications (React, Vue, etc.)
 * - api: Backend API servers (Express, Fastify, etc.)
 * - mcp: MCP server implementations
 * - openclaw: OpenClaw AI agent projects (SKILL.md, HEARTBEAT.md)
 * - all: Applies to all project types
 */
export type ProjectType = 'cli' | 'library' | 'sdk' | 'webapp' | 'api' | 'mcp' | 'openclaw' | 'all';

export interface SecurityCheck {
  id: string;
  name: string;
  description: string;
  category: string;
  severity: Severity;
  /** Function to detect if the issue exists */
  detect: () => Promise<CheckResult>;
  /** Function to fix the issue (if auto-fixable) */
  fix?: () => Promise<FixResult>;
}

export interface CheckResult {
  passed: boolean;
  message: string;
  details?: Record<string, unknown>;
}

export interface FixResult {
  success: boolean;
  message: string;
  details?: Record<string, unknown>;
}

export interface SecurityFinding {
  checkId: string;
  name: string;
  description: string;
  category: string;
  severity: Severity;
  passed: boolean;
  message: string;
  fixable: boolean;
  fixed?: boolean;
  fixMessage?: string;
  /** Set after fix: true if re-scan confirms the issue is resolved */
  fixVerified?: boolean;
  /** Set in dry-run mode to indicate this would be fixed */
  wouldFix?: boolean;
  /**
   * This finding sits inside the archive THIS `--fix` run created
   * (`.hackmyagent-backup/<stamp>/`), proven by `dev`+`ino` identity.
   *
   * #374 — it counts against the score exactly like any other finding, because
   * the archive really does hold a plaintext copy of the credential and every
   * later scan will report it (that inclusion is the deliberate #305/#309/#341
   * decision, restated at `scanner.ts:4769`). The flag exists so the report can
   * ATTRIBUTE the difference between the score and the score the tree would
   * have without the archive — not to exempt anything.
   *
   * Set only for the current run's own archive. A pre-existing archive, or a
   * directory elsewhere in the tree merely named `.hackmyagent-backup`, is an
   * ordinary finding and is never flagged.
   */
  inOwnArchive?: boolean;
  /** File path where the issue was found (relative to scan directory) */
  file?: string;
  /** Line number in the file where the issue was found */
  line?: number;
  /** Runnable command or concise action to fix this issue */
  fix?: string;
  /**
   * Remedy to cite when the auto-fix ran but the verification pass proved it
   * did not land. `fix` normally names the auto-fix itself, which is a dead
   * end once that auto-fix is the thing that failed. Checks that have a
   * runnable manual equivalent supply it here.
   */
  manualFix?: string;
  /** Human-readable explanation of why this matters and how to remediate */
  guidance?: string;
  /** Attack taxonomy class this finding maps to (e.g., "CRED-HARVEST") */
  attackClass?: string;
  details?: Record<string, unknown>;
  /**
   * Structured evidence (positive | absence | mixed). Optional in v0.21.x;
   * mandatory in v0.22+. See `src/types/finding-evidence.ts`.
   */
  evidence?: Evidence;
  /** Plain-English rationale grounded in the evidence. Optional in v0.21.x. */
  rationale?: Rationale;
  /** Tag for an unfamiliar primitive the fix recommends (renderer dedupes per scan). */
  concept?: ConceptId;
  /**
   * Advisory NanoMind read of the artifact this finding sits in. Signal-only —
   * it is consumed by the trust score, ARIA, and the Agent Threat Matrix and
   * NEVER affects this finding's severity, pass/fail, or the computed score.
   * Present only when the non-generative classifier actually ran on the artifact
   * (not the heuristic fallback). See `NanoMindIntentSignal`.
   */
  nanomindIntent?: NanoMindIntentSignal;
}

/**
 * Per-artifact advisory classification from the NanoMind non-generative
 * classifier (Mamba-TME ONNX — run in-process or via the local daemon), as the
 * compiler determined it for the whole artifact. This is the model's inference
 * with deterministic safety adjustments applied (e.g. a regex manipulation guard
 * may elevate a benign model label to `suspicious`); it is NOT the raw,
 * uninterpreted ONNX argmax. Attached to every finding on that artifact as a
 * signal for downstream consumers (trust score / ARIA / Agent Threat Matrix).
 * Purely informational: it does not enter HMA's severity, scoring, or any deny
 * path. Because the judgment is a classification (not a generation), an artifact
 * cannot hijack the judge by embedding instructions in its own text.
 */
export interface NanoMindIntentSignal {
  /** Classifier verdict for the whole artifact (with deterministic safety adjustments). */
  classification: 'benign' | 'suspicious' | 'malicious';
  /** Classifier confidence in [0, 1]. */
  confidence: number;
  /** NanoMind model version that produced the classification (e.g. nanomind-tme-v0.5.0). */
  modelVersion: string;
}

export interface ScanResult {
  timestamp: Date;
  platform: string;
  /** Detected project type */
  projectType: ProjectType;
  /** Filtered findings (failed checks with file paths) - for CLI display */
  findings: SecurityFinding[];
  /** All findings including passed checks - for benchmark evaluation */
  allFindings?: SecurityFinding[];
  /**
   * Composite score as rendered and published. Clamped out of the "good"
   * band whenever the scan's own verdict is fail-direction (>=1 critical or
   * high), so the number can never read "good" next to a "Not safe" verdict
   * (#259). When `scoreClamped` is true this is less than `rawScore`.
   */
  score: number;
  maxScore: number;
  /**
   * Pre-clamp composite, straight from `calculateSecurityScore`. Preserved
   * so the clamp is information-adding rather than information-destroying —
   * same shape as the scan-soul #206/#251 clamp.
   */
  rawScore?: number;
  /** True when `score < rawScore` because the verdict is fail-direction (#259). */
  scoreClamped?: boolean;
  /**
   * What `score` would be if the archive this `--fix` run just created were not
   * there — i.e. the score of the user's live tree.
   *
   * #374 — `--fix` used to announce a score computed with its own archive
   * excluded, while every later scan computed one including it. Measured on a
   * three-file fixture: `--fix` announced 69 and the immediate rescan said 59,
   * with nothing changed in between. The two numbers described different trees
   * and could not agree, and the one the user saw again was never the one they
   * were told.
   *
   * `score` is now always the number the next scan will produce, so this field
   * carries the OTHER number rather than replacing it: the report headlines
   * `score` and names this one as what the tree is worth once the archived copy
   * is rotated and deleted. Present only on a run that created a non-empty
   * archive AND whose archive contributed at least one finding; `undefined`
   * otherwise, so `undefined` never has to be read as "same as score".
   *
   * Derived from the same findings array `score` is, at every one of the eight
   * points the CLI re-settles the score (`applyScore`), so the two can never be
   * computed off different evidence.
   */
  scoreExcludingOwnArchive?: number;
  /** Path to backup directory (only set when autoFix is true and not dryRun) */
  backupPath?: string;
  /** True if this was a dry-run (no changes made) */
  dryRun?: boolean;
  /** True if all fixes completed atomically (or rolled back on failure) */
  atomicFix?: boolean;
  /** List of check IDs that were ignored */
  ignored?: string[];
  /** Semantic analysis summary (Layer 2 + Layer 3) */
  semanticAnalysis?: {
    layer2Findings: number;
    layer3Findings: number;
    llmCost?: number;
    cachedResults?: number;
  };
  /**
   * Summaries of AI runtimes installed on this machine but OUTSIDE the scan
   * target (`~/.openclaw`, `~/.nemoclaw`, ...).
   *
   * [CHIEF-CA 2026-08-03] Reported, never scored. Nothing here has ever been
   * counted in `findings`, `score`, or the exit code — a directory-scoped
   * score has to mean the directory, or `--fail-below` is not a CI gate.
   * Consumers that aggregate `findings` get the target's findings only.
   */
  machinePosture?: MachinePostureSummary[];
  /**
   * What this scan ACTUALLY examined, measured at runtime.
   *
   * Before this existed, the Observations block derived its coverage claim
   * from `TAXONOMY_MAP` — the configured check set — so `310 static · 0
   * skipped · (all clear)` was printed identically whether the checks ran
   * against the tree or not. Measured on a 528-file repo carrying a planted
   * credential and a `curl … | sh`, the output was byte-identical to the
   * unplanted tree's. Every field here is evidence from the run.
   */
  coverage?: {
    /** Distinct files inside the target whose contents the scan read. */
    filesExamined: number;
    /** Per-check-method execution records. */
    executions: CoverageCheckExecution[];
    /** Caps that stopped a layer short of the whole tree. */
    truncations: CoverageTruncationRecord[];
  };
}

/** One check method's execution record. Mirrors `CheckExecution`. */
export interface CoverageCheckExecution {
  method: string;
  prefixes: string[];
  completed: boolean;
  filesRead: number;
  pathsInspected: number;
  skipReason?: string;
  error?: string;
}

/** One cap that stopped a layer short. Mirrors `CoverageTruncation`. */
export interface CoverageTruncationRecord {
  layer: string;
  cap: number;
  prefixes: string[];
  reason: string;
}

/**
 * One auto-detected AI runtime outside the scan target: the SUMMARY of scanning
 * it, not its findings. A real `~/.openclaw` measured 1780 findings — enumerating
 * them into a target-scoped report buries the target's own.
 */
export interface MachinePostureSummary {
  /** Vendor label, e.g. `OpenClaw`. */
  name: string;
  /** Home-relative display path (`~/.openclaw`). Never the absolute path. */
  dir: string;
  /**
   * Runnable command that scans this scope properly, or `null` when no correct
   * command can name the path — a home directory carrying a control byte has no
   * truthful citation, and the `<dir>` placeholder is shell redirection.
   */
  scanCommand: string | null;
}

/**
 * Lifecycle stages for context evolution analysis.
 *
 * Stage 0 (static): Current HMA scan -- files on disk as-is.
 * Stage 1 (assembly): System prompt assembly simulation -- models how
 *   components (SOUL.md, tool descriptions, memory, user prefs) combine
 *   into the final system prompt, detecting injections that survive assembly.
 * Stage 2 (runtime): Future -- runtime behavior monitoring via ARP.
 */
export type LifecycleStage = 0 | 1 | 2;

/**
 * A component that contributes to the assembled system prompt.
 * Each component has a source file, role, and raw content.
 */
export interface AssemblyComponent {
  /** Source file path (relative to scan directory) */
  source: string;
  /** Component role in the assembly pipeline */
  role: 'soul' | 'toolDescription' | 'memory' | 'userPreference' | 'conversationHistory' | 'systemInstruction';
  /** Raw content before assembly */
  content: string;
  /** Byte offset in the assembled prompt where this component starts */
  assembledOffset?: number;
  /** Byte length of this component in the assembled prompt */
  assembledLength?: number;
}

/**
 * Result of an assembly-stage interaction analysis.
 * Tracks which components combined to create a finding.
 */
export interface AssemblyInteraction {
  /** Components involved in this interaction */
  components: string[];
  /** Type of cross-component attack detected */
  attackType: 'crossComponentInjection' | 'displacementAttack' | 'priorityHijack' | 'instructionDilution' | 'semanticSplit';
  /** The assembled text segment that triggered detection */
  assembledSegment: string;
  /** Confidence that this is a real attack (0-1) */
  confidence: number;
}

/**
 * Wraps a ScanResult with lifecycle stage metadata.
 * Stage 0 results are backward-compatible with plain ScanResult.
 */
export interface LifecycleScanResult {
  /** The lifecycle stage this result covers */
  stage: LifecycleStage;
  /** The underlying scan result for this stage */
  scanResult: ScanResult;
  /** Components discovered during assembly simulation (Stage 1+) */
  assemblyComponents?: AssemblyComponent[];
  /** Cross-component interactions detected (Stage 1+) */
  assemblyInteractions?: AssemblyInteraction[];
  /** The fully assembled system prompt (Stage 1+) */
  assembledPrompt?: string;
  /** Total token estimate of the assembled prompt */
  assembledTokenEstimate?: number;
}
