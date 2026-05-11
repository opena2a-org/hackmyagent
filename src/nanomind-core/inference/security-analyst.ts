/**
 * NanoMind Security Analyst — IPC client into the NanoMind-Guard daemon.
 *
 * The v3 generative analyst (Qwen3-1.7B SFT) and its input-classifier gate
 * run inside the NanoMind-Guard daemon — a Python process that loads the
 * model once, verifies artifact integrity (joblib is pickle; SHA256 is
 * mandatory), and serves classification over a Unix socket.
 *
 * HMA used to download the GGUF/safetensors directly from HuggingFace and
 * shell out to mlx_lm or llama_cpp_python per request. That path bypassed
 * the input-classifier gate and produced a 34% off-topic refusal rate on
 * benign inputs. Routing through the daemon brings the model card's 92%
 * gated rate to real users.
 *
 * On daemon-absent or unhealthy: returns null. Callers treat null as
 * "analyst unavailable" — the analyst is opt-in behind --nanomind, so
 * null is not a benign verdict. Never fall back to direct HF download:
 * the input-classifier gate is the whole point.
 *
 * The v3 NLM emits a single universal classifier response shape
 * (predictedAttackClass, severity, analysis, verdict, evidence,
 * remediation). The shapeResultForTask adapter below maps the universal
 * shape into the task-specific result fields that orchestrate.ts and the
 * CLI renderer expect (threatLevel/attackVector/description/mitigations
 * for threatAnalysis, classification/reasoning for credential context,
 * isFalsePositive/reasoning for FP detection, etc.). Nuanced credential
 * detection (placeholder vs example vs test) collapses to a binary
 * real/test split — task-specific credential models are deferred.
 */

import {
  sendClassify,
  sendHealthz,
  isDaemonHealthy,
  isClassifyOk,
  DEFAULT_SOCK_PATH,
  type ClassifyOkResponse,
  type HealthzResponse,
} from './nanomind-guard-client.js';

// ============================================================================
// Public types (preserved across the 0.22 → 0.23 rewrite)
// ============================================================================

export type AnalystTaskType =
  | 'threatAnalysis'
  | 'credentialContextClassification'
  | 'falsePositiveDetection'
  | 'artifactClassification'
  | 'checkExplanation'
  | 'governanceReasoning'
  | 'intelReport';

export interface AnalystRequest {
  taskType: AnalystTaskType;
  content: string;
  context?: string;
}

export interface AnalystResponse {
  taskType: AnalystTaskType;
  result: Record<string, unknown>;
  confidence: number;
  modelVersion: string;
  durationMs: number;
  backend: AnalystBackend;
  /**
   * Whether the verdict came from the input-classifier gate (binary
   * off-topic bypass) or the NLM (per-artifact attack classification).
   * Renderer can use this to distinguish "binary gate decision"
   * (confidence is not a probability) from "NLM measured confidence."
   */
  source?: 'input-classifier-gate' | 'nlm';
}

export interface ThreatAnalysis {
  threatLevel: string;
  attackVector: string;
  description: string;
  mitigations: string[];
  confidence: number;
}

export interface CredentialContext {
  classification: 'real' | 'test' | 'example' | 'placeholder' | 'unknown';
  reasoning: string;
  confidence: number;
}

export interface FalsePositiveAssessment {
  isFalsePositive: boolean;
  reasoning: string;
  confidence: number;
}

export type AnalystBackend = 'daemon' | 'none';

export interface AnalystStatus {
  available: boolean;
  backend: AnalystBackend;
  /** Kept for backward compatibility; true iff the daemon answers /healthz. */
  modelCached: boolean;
  platform: string;
  setupCommand: string;
  /** Full /healthz body when reachable; null otherwise. */
  daemon: HealthzResponse | null;
}

// ============================================================================
// Constants
// ============================================================================

const MODEL_VERSION = '3.0.0';

/**
 * Client-side input cap. The daemon enforces 1 MB on its side and truncates
 * the encoder context to 256 tokens silently; 4 KB is generous for per-finding
 * security artifact analysis and avoids shipping noise to the model.
 */
const MAX_INPUT_CHARS = 4096;

// ============================================================================
// Status & setup
// ============================================================================

export async function getAnalystStatus(): Promise<AnalystStatus> {
  const daemon = await sendHealthz();
  const platform = process.platform === 'darwin'
    ? 'Apple Silicon (NanoMind-Guard daemon)'
    : `${process.platform} (daemon not supported)`;
  if (daemon === null) {
    return {
      available: false,
      backend: 'none',
      modelCached: false,
      platform,
      setupCommand: 'hackmyagent nanomind setup',
      daemon: null,
    };
  }
  return {
    available: daemon.ok,
    backend: 'daemon',
    modelCached: daemon.ok,
    platform,
    setupCommand: 'hackmyagent nanomind setup',
    daemon,
  };
}

export async function isAnalystReady(): Promise<boolean> {
  return isDaemonHealthy();
}

/**
 * Print install instructions for the NanoMind-Guard daemon. The daemon is a
 * separate Python sidecar; HMA does not bundle it. A one-line installer is
 * shipping in the opena2a-nanomind-guard package; until then this prints
 * manual install steps.
 *
 * Returns true iff the daemon is already running. Returns false otherwise.
 */
export async function setupAnalystModel(quiet = false): Promise<boolean> {
  const healthy = await isDaemonHealthy();
  if (healthy) {
    if (!quiet) {
      process.stderr.write(
        'NanoMind-Guard daemon is already running.\n' +
        'Use --nanomind with any scan command for AI-powered analysis.\n',
      );
    }
    return true;
  }

  if (process.platform !== 'darwin') {
    if (!quiet) {
      process.stderr.write(
        'NanoMind v3 currently requires Apple Silicon Mac.\n' +
        'Linux and cloud daemon builds are tracked as a separate workstream.\n' +
        'Run scans without --nanomind on this platform.\n',
      );
    }
    return false;
  }

  if (!quiet) {
    process.stderr.write(
      'NanoMind-Guard daemon is not running.\n' +
      '\n' +
      'The v3 generative analyst routes through the NanoMind-Guard daemon —\n' +
      'a small Python sidecar that loads the v3 NLM and the input-classifier\n' +
      'gate and serves classification on a Unix socket. HMA does not bundle\n' +
      'the daemon; a one-line installer is shipping in opena2a-nanomind-guard.\n' +
      '\n' +
      'Manual install steps are in the daemon repo:\n' +
      '  https://github.com/opena2a-org/nanomind-training#nanomind-guard\n' +
      '\n' +
      `Default socket path: ${DEFAULT_SOCK_PATH}\n` +
      'Override with NANOMIND_GUARD_SOCK=/path/to/your.sock\n' +
      '\n' +
      'After install, verify with: hackmyagent nanomind status\n',
    );
  }
  return false;
}

// ============================================================================
// Inference
// ============================================================================

/**
 * Run analyst inference via the daemon. Returns null when:
 *   - daemon is absent / unreachable / unresponsive
 *   - daemon returns an ERR_* error response
 *   - daemon response cannot be parsed
 *
 * On success, returns an AnalystResponse with the result field shaped to the
 * task-specific contract that the CLI renderer and orchestrator expect.
 */
export async function runAnalystInference(
  request: AnalystRequest,
): Promise<AnalystResponse | null> {
  const startMs = Date.now();
  const truncatedContent = request.content.slice(0, MAX_INPUT_CHARS);
  const inputText = request.context
    ? `${request.context}\n\n${truncatedContent}`
    : truncatedContent;

  const response = await sendClassify(inputText);
  if (response === null || !isClassifyOk(response)) {
    return null;
  }

  const result = shapeResultForTask(response, request.taskType);
  const confidence = typeof response.confidence === 'number'
    ? response.confidence
    : (typeof result.confidence === 'number' ? result.confidence : 0.5);

  return {
    taskType: request.taskType,
    result,
    confidence,
    modelVersion: `nanomind-analyst-v${MODEL_VERSION}`,
    durationMs: Date.now() - startMs,
    backend: 'daemon',
    source: response.source === 'input-classifier-gate' ? 'input-classifier-gate' : 'nlm',
  };
}

/**
 * Adapt the daemon's universal classifier response to the task-specific
 * fields each renderer in cli.ts reads. The v3 NLM is a unified
 * security-artifact classifier and does not accept per-task system prompts;
 * the task shape is constructed here on the client side from the universal
 * verdict.
 */
function shapeResultForTask(
  response: ClassifyOkResponse,
  taskType: AnalystTaskType,
): Record<string, unknown> {
  // Sanitize every daemon-controlled string at the boundary. The CLI
  // renderer prints these to a terminal, so ANSI / OSC / C0-C1 control
  // sequences in a hostile daemon response could rewrite the terminal
  // title, clear the screen, inject hyperlinks, or mask the displayed
  // verdict. Sanitization is applied once here instead of at every
  // render site so a future render addition can't accidentally skip it.
  const analysis = sanitizeAnalystString(response.analysis);
  const verdict = sanitizeAnalystString(response.verdict);
  const evidence = sanitizeAnalystString(response.evidence);
  const remediation = sanitizeAnalystString(response.remediation);
  const severity = sanitizeAnalystString(response.severity).toLowerCase();
  const attackClass = sanitizeAnalystString(response.predictedAttackClass);
  const classification = sanitizeAnalystString(response.classification);
  const isBenign = classification === 'benign' || attackClass === 'none';

  const splitLines = (s: string): string[] =>
    s.split(/\r?\n/).map(line => line.trim()).filter(Boolean);

  const remediationItems = splitLines(remediation);
  const evidenceItems = splitLines(evidence);
  const confidence = typeof response.confidence === 'number'
    ? response.confidence
    : 0.5;

  switch (taskType) {
    case 'threatAnalysis':
      return {
        threatLevel: severity || (isBenign ? 'none' : 'unknown'),
        attackVector: attackClass !== 'none' ? attackClass : '',
        description: analysis,
        mitigations: remediationItems,
        confidence,
      };
    case 'credentialContextClassification':
      // Universal classifier collapses placeholder/example/test detection
      // into the general benign/malicious split. 'real' vs 'test' is the
      // best signal we can derive without a task-specific credential model.
      return {
        classification: isBenign ? 'test' : 'real',
        reasoning: analysis,
        confidence,
      };
    case 'falsePositiveDetection':
      return {
        isFalsePositive: isBenign,
        reasoning: analysis,
        confidence,
      };
    case 'artifactClassification':
      return {
        artifactType: attackClass !== 'none' ? attackClass : 'benign',
        reasoning: analysis,
        confidence,
      };
    case 'checkExplanation':
      return {
        explanation: analysis,
        impact: verdict,
        recommendation: remediation,
        confidence,
      };
    case 'governanceReasoning':
      return {
        gaps: evidenceItems,
        strengths: [],
        recommendations: remediationItems,
        confidence,
      };
    case 'intelReport':
      return {
        summary: analysis,
        keyFindings: evidenceItems,
        riskAssessment: verdict,
        recommendations: remediationItems,
        confidence,
      };
    default:
      return { confidence, ...(response as unknown as Record<string, unknown>) };
  }
}

function stringOrEmpty(v: unknown): string {
  return typeof v === 'string' ? v : '';
}

/**
 * Strip control characters and ANSI escape sequences from a daemon-supplied
 * string before it flows to the renderer. The daemon is a separate process
 * reachable over a Unix socket whose path can be overridden via
 * NANOMIND_GUARD_SOCK; defense-in-depth treats every string field as
 * untrusted at the IPC boundary.
 *
 * Removes: CSI / OSC / DCS escape sequences, BEL, C0 controls except \n
 * and \t, all C1 controls. Preserves the visible UTF-8 content unchanged.
 */
function sanitizeAnalystString(v: unknown): string {
  if (typeof v !== 'string') return '';
  return v
    // CSI sequences:  ESC [ ... letter  (color codes, cursor moves, clear screen)
    .replace(/\x1b\[[0-9;?]*[ -\/]*[@-~]/g, '')
    // OSC sequences:  ESC ] ... BEL  (terminal title, hyperlinks)
    .replace(/\x1b\][\s\S]*?(?:\x07|\x1b\\)/g, '')
    // DCS / SOS / PM / APC sequences
    .replace(/\x1b[PX^_][\s\S]*?(?:\x07|\x1b\\)/g, '')
    // Bare ESC, BEL, and other C0 controls except \n, \t
    .replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, '')
    // C1 controls (8-bit)
    .replace(/[\x80-\x9f]/g, '');
}

// ============================================================================
// Task-specific wrappers
// ============================================================================

export async function analyzeThreat(
  content: string,
  attackClass: string,
): Promise<ThreatAnalysis | null> {
  const response = await runAnalystInference({
    taskType: 'threatAnalysis',
    content,
    context: `Detected attack class: ${attackClass}`,
  });
  if (!response) return null;
  const r = response.result;
  return {
    threatLevel: String(r.threatLevel ?? 'unknown'),
    attackVector: String(r.attackVector || attackClass),
    description: String(r.description ?? ''),
    mitigations: Array.isArray(r.mitigations) ? r.mitigations.map(String) : [],
    confidence: response.confidence,
  };
}

export async function assessCredentialContext(
  content: string,
): Promise<CredentialContext | null> {
  const response = await runAnalystInference({
    taskType: 'credentialContextClassification',
    content,
  });
  if (!response) return null;
  const r = response.result;
  const validClasses = ['real', 'test', 'example', 'placeholder', 'unknown'] as const;
  const classification = validClasses.includes(r.classification as typeof validClasses[number])
    ? (r.classification as CredentialContext['classification'])
    : 'unknown';
  return {
    classification,
    reasoning: String(r.reasoning ?? ''),
    confidence: response.confidence,
  };
}

export async function assessFalsePositive(
  content: string,
  findingDescription: string,
): Promise<FalsePositiveAssessment | null> {
  const response = await runAnalystInference({
    taskType: 'falsePositiveDetection',
    content,
    context: `Finding: ${findingDescription}`,
  });
  if (!response) return null;
  const r = response.result;
  return {
    isFalsePositive: Boolean(r.isFalsePositive),
    reasoning: String(r.reasoning ?? ''),
    confidence: response.confidence,
  };
}

export async function generateIntelReport(
  findingsSummary: string,
): Promise<AnalystResponse | null> {
  return runAnalystInference({
    taskType: 'intelReport',
    content: findingsSummary,
  });
}
