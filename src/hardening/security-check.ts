/**
 * Security check types and interfaces
 */

import type { Evidence, Rationale, ConceptId } from '../types/finding-evidence';
import type { ShapeId } from '../types/credential-format';
// Type-only, and therefore erased: `finding-emit` imports types from here, so a
// value import would be a runtime cycle. This one is not.
import type { RedactedFinding } from './finding-emit';
import { FIX_LINES } from './fix-lines';

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

/**
 * Which route the caller used to ask for a finding to be left out of the
 * report (#450). Named rather than a bare string so the disclosure can say
 * which knob was turned, and so a fourth channel cannot be added without
 * touching this union.
 */
export type SuppressionChannel = 'ignore-flag' | 'hmaignore-check' | 'hmaignore-path';

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
  /**
   * Whether the check found its subject and MEASURED it clean.
   *
   * #458 — three states, not two. `true`: measured, clean. `false`: measured,
   * defective (or, for an absent-mitigation advisory, `file` is the path the
   * fix creates — GIT-001 / SANDBOX-001 shape). OMITTED: nothing was measured
   * and `notApplicable` says why. A consumer that reads `passed` as a boolean
   * turns the third state into whichever of the other two its comparison
   * favours (`!== false` credits an unmeasured control as passed, `!f.passed`
   * scores it as failed), so a consumer tests `notApplicable` first.
   */
  passed?: boolean;
  /**
   * #458 — the check's subject does not exist in this tree (a not-there errno:
   * `coverage-ledger.ts` `countsAsUnread` is false), so the check measured
   * nothing. `subject` names what was looked for (`Dockerfile`, `.mcp.json`,
   * `source files`); `reason` says why that makes the check not applicable
   * rather than failed. Carried WITHOUT `passed`, without severity weight and
   * without a score contribution (`countsAgainstScore` and `retainForVerdict`
   * both return false on it before reading anything else).
   *
   * Not for a subject that MUST exist: a required artifact's absence is a
   * failure with `file` set to the path the fix creates, never this. Any errno
   * other than not-there is an unread input (`buildUnreadInputFinding`), never
   * this either.
   */
  notApplicable?: { subject: string; reason: string };
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
  /**
   * The USER asked for this finding to be left out of the report — `--ignore`,
   * an `.hmaignore` check-ID pattern, or an `.hmaignore` path pattern.
   *
   * #450. It is MARKED, not removed. A suppressed finding still counts toward
   * `score`, `rawScore`, the verdict band and the exit code; it is dropped from
   * the rendered findings LIST and disclosed by name on a `Suppressed` line.
   * Declining to look at a check may not make a tree score better than looking
   * at it, and before this flag existed it did: one `--ignore` moved
   * `corpus/repo/buggy/leaky-env-example` from 69/100 exit 1 to 98/100 exit 0
   * with the credential verdict gone and nothing in the output naming the
   * suppression.
   *
   * Marking rather than filtering is deliberate. Every score and exit path in
   * this codebase keys off `countsAgainstScore` (`src/ui/verdict-band.ts`),
   * which is documented there as the single predicate behind both the score and
   * the fail direction — so leaving these findings in the array makes all five
   * output channels honest without five separate repairs, and inverts the
   * failure mode: a display site that forgets to filter shows a suppressed
   * finding (loud, safe) instead of laundering the score (silent, not).
   */
  suppressed?: boolean;
  /** Which suppression channel asked for it. Set whenever `suppressed` is. */
  suppressedBy?: SuppressionChannel;
  /** File path where the issue was found (relative to scan directory) */
  file?: string;
  /**
   * For `SCAN-UNREAD-001`: whether `file` names a file the scan could not read
   * or a directory it could not list (#588). Absent on every other finding.
   */
  kind?: 'file' | 'directory';
  /** Line number in the file where the issue was found */
  line?: number;
  /** Runnable command or concise action to fix this issue */
  fix?: string;
  /**
   * #367 — `fix` as the lines its producer authored, carried beside the
   * joined string rather than recovered from it: a boundary between elements
   * is trusted line structure, a newline inside an element is not. Holds only
   * while the elements join to `fix`; `emitFinding` drops a pair that
   * disagrees. Text channel only: the key is a symbol, which `JSON.stringify`
   * never serializes, so no JSON channel carries it from any site.
   */
  readonly [FIX_LINES]?: readonly string[];
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
  /**
   * Always present. Whether this finding's byte-carrying fields passed the
   * redaction boundary (`emitFinding`), and what the boundary concluded.
   *
   * `'unverified'` is the DEGRADED value, not an initializer: no construction
   * path sets it — every construction emits. It is what a publish boundary
   * would stamp on a finding-shaped value carrying no redaction provenance IF
   * its fail-mode were not to throw — an explicit unknown, never a claim of
   * cleanliness. Under the shipped fail-mode (`[CHIEF-CISO]` 2026-08-21, throw
   * in every environment) it has no producer, and `assertRedactionProvenance`
   * REJECTS it at every publish boundary: it may exist on a value in process,
   * it may never cross a channel. (`[CHIEF-CA]` 2026-08-21 corrected the
   * earlier "INITIALIZER" wording here, which described semantics nothing
   * implemented — the reader is the implementation now.)
   *
   * `[ABDEL]` 2026-08-13 (D3). Field name, type and the always-present rule are
   * FROZEN, as is the closed three-member union.
   */
  redactionStatus: 'applied' | 'clean' | 'unverified';
  /**
   * Always present. Registry shape ids the redactor resolved FROM THE VALUE.
   *
   * `[]` unless `'applied'` — and `'applied'` with `[]` is valid and honest,
   * because a key-name or context heuristic resolves no shape (C9). Sorted and
   * deduped.
   *
   * `ShapeId`'s MEMBERSHIP is deliberately open (22 today; GAP-8 grows it).
   * `readonly ShapeId[]` here, `string[]` in the published schema — consumers
   * MUST tolerate an id they have not seen. Do not publish this as a
   * string-literal union: that freezes the vocabulary by accident and makes
   * every future credential shape a breaking change.
   *
   * Forbidden on this pair, now and after the freeze: `redactionCount`, byte
   * offsets, any length / `totalChars` / `byteLength` / character count, any
   * preserved prefix or suffix, any hash or fingerprint of the body, salted or
   * not. The predicate: a redaction field may carry CLASSIFICATION, never a
   * MEASUREMENT OF THE BODY.
   */
  redactedShapes: readonly ShapeId[];
}

/**
 * What a PRODUCER writes: every field of a finding except the two the
 * redaction boundary stamps.
 *
 * A detector cannot write `redactionStatus` or `redactedShapes`, because a
 * detector is not in a position to know them — only `emitFinding`
 * (`src/hardening/finding-emit.ts`) is. Producer-side accumulators, the private
 * check methods that fill them, and every hand-written adapter therefore carry
 * `SecurityFindingDraft[]`; the two redaction fields appear exactly when a value
 * crosses the boundary and not one line earlier.
 *
 * This is the type that makes the boundary provable rather than asserted. The
 * settlement brief's claim that four route points cover every construction site
 * was an unverified premise (CA rejected it as such): with the two fields
 * REQUIRED on `SecurityFinding`, the compiler enumerates the real set, and it
 * found three producers the four-point route set did not name
 * (`skill-capability-validator.ts:167`, `cli.ts:4341`, `cli.ts:1575`).
 */
export type SecurityFindingDraft = Omit<
  SecurityFinding,
  'redactionStatus' | 'redactedShapes'
>;

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
  /**
   * Filtered findings (failed checks with file paths) - for CLI display.
   *
   * `RedactedFinding`, not `SecurityFinding`: this is what makes C10's brand
   * load-bearing rather than decorative. A `ScanResult` cannot be built from
   * findings that did not cross `emitFinding`, because no other module can
   * produce the brand — so a future channel that assembles its own result is a
   * COMPILE error rather than a silent leak.
   */
  findings: RedactedFinding[];
  /** All findings including passed checks - for benchmark evaluation. Branded
   *  for the same reason: it is a second published channel, not a view. */
  allFindings?: RedactedFinding[];
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
  /**
   * Findings an `.hmaignore` PATH rule put out of scope (#450).
   *
   * Not in `findings`, not in `score`, not in the exit code — a path rule is a
   * scope statement ("this part of the tree is not my product"), the same
   * statement as scanning a subdirectory, and a smaller target honestly scores
   * differently. This array is the only record that the scan was narrowed, so
   * it is what stops the narrowing being silent, and every renderer is expected
   * to surface it. Identity only, per `summarizeSuppressed`.
   *
   * Distinct from a check-ID suppression (`--ignore`, an `.hmaignore`
   * `!CHECK-ID` line), which is NOT a scope change: the check ran over the whole
   * tree and matched, so it stays in `findings` marked `suppressed` and keeps
   * counting.
   */
  outOfScope?: Array<{ checkId: string; name: string; category: string; severity: string; count: number; suppressedBy: string }>;
  /**
   * Check IDs the caller suppressed with `--ignore` or an `.hmaignore`
   * `!CHECK-ID` rule (#450).
   *
   * NOT in `findings`, because that array is also the input to the `--fix`
   * governance auto-fix, the Registry publish payload, `allFindings` in
   * `--json`, and every report format — leaving suppressed entries in it made
   * `secure --fix --ignore X` write a `SOUL.md` for the suppressed check and
   * made `--json` ship the finding's plaintext credential evidence.
   *
   * Their penalties ARE in `score`, and any code that re-derives a score, a
   * verdict band or an exit code from `findings` must add them back with
   * `expandSuppressed` or the laundering this field exists to stop comes back.
   */
  suppressed?: Array<{ checkId: string; name: string; category: string; severity: string; count: number; suppressedBy: string }>;
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
   * against the tree or not. Measured on a 529-file repo carrying a planted
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
    /** Distinct files read per category. Counts only — never filenames. */
    filesReadByCategory?: Record<string, number>;
    /**
     * Inputs inside the target that were discovered and could not be read —
     * `EACCES`, `EPERM`, `EIO` and every other errno EXCEPT the three that mean
     * "no file of the kind sought is at that path": `ENOENT` (nothing there),
     * `EISDIR` (a directory there) and `ENOTDIR` (a path component is a file).
     * Those three are excluded because a probe for a config spelling that does
     * not exist found nothing to examine, which is honest, and is the case
     * `tracked-fs` attributes on resolve for.
     *
     * `coverage-ledger.ts`'s `countsAsUnread` is the single authority on that
     * set; this sentence must be read as describing it, never as a second copy.
     * #438's design brief named `EISDIR` as a code that SHOULD gate — counting
     * it fires on every real repository (9 on hackmyagent's own tree, 10 on
     * atlas), which is why the measurement overrode the brief.
     *
     * The unit `secure`'s completeness gate is derived from (#438). It is
     * deliberately not a files-read threshold: the reverted fix moved the bar
     * from 0 files to 1, and `secure --fix` then satisfied its own gate by
     * writing a `.gitignore` into the target and scoring itself 100/100. An
     * unread input cannot be cleared by writing a new readable file — the
     * `EACCES` recorded on the other one is still there.
     *
     * Counts and errno codes, never paths. The paths reach the user through a
     * finding, which is the channel that carries `file:line` and a fix.
     *
     * `count` includes BOTH kinds of lost input: a file the scan discovered
     * and could not read, and a directory it discovered and could not list
     * (#588) — one unit per obstruction, never an estimate of what a directory
     * hid. `directories` is the kind split and is always present, `0` included.
     */
    unreadableInputs?: { count: number; codes: Record<string, number>; directories: number };
    /**
     * FAILED checks that MATCHED something in the tree and were dropped from
     * `findings` anyway, because the check's prefix is out of scope for the
     * detected project type.
     *
     * Evidence-bearing only: every entry corresponds to a finding that carried
     * a file. Failed checks with nothing to point at — "no rate limiting
     * detected" on a library with no HTTP server — are counted in
     * `unevidencedFailures` instead, because they report an absence rather
     * than a discovery and do not make a `clear` claim false.
     *
     * Exists so the renderer cannot report a category `clear` while that
     * category holds a real detection nobody was shown (#421). `clear` is a
     * claim of "examined and found nothing"; a hidden match makes it false.
     * This is the same contract as the coverage object itself, one layer
     * deeper: that stopped an UNEXAMINED category printing clear, this stops
     * an examined-but-silenced one.
     *
     * Carries the check's own identity ONLY — no file paths and no messages,
     * so it keeps the "never emit read paths" discipline of the fields above.
     * These are the identity fields the renderer's category classifier reads
     * (it also reads `passed`, which the consumer supplies as `false`), which
     * is the point: the consumer classifies these through the SAME function it
     * classifies real findings with, so the two cannot drift into different
     * category vocabularies. (`LOG-*` findings carry `category: 'logging'` but
     * render under the label `audit` — a set keyed by the raw category would
     * silently never match.)
     *
     * Findings the USER suppressed (`--ignore`, `.hmaignore`) are deliberately
     * absent: that suppression was requested, and is already disclosed
     * through `ignored`.
     */
    suppressedFailures?: Array<{
      checkId: string;
      name: string;
      category: string;
      severity: string;
    }>;
    /**
     * Count of failed checks that produced no evidence — an absent mitigation
     * rather than a discovery — and were therefore not shown.
     *
     * A count and not a list on purpose. These are dominated by checks that
     * cannot pass on a project shape that does not need them (`SQL Injection
     * Protection` on a library with no database), so naming them per category
     * would read as an accusation with no path forward. The number exists so
     * the volume is visible and can be attacked at the check level later.
     */
    unevidencedFailures?: number;
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
