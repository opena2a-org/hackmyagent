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

import { execFileSync } from 'node:child_process';
import { realpathSync, statSync } from 'node:fs';
import { dirname } from 'node:path';
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
 * Drive setup of the NanoMind-Guard daemon. The daemon is a separate Python
 * sidecar; HMA does not bundle it. The daemon installer ships as the
 * nanomind-analyst PyPI package — if it is on $PATH this function shells out
 * to `nanomind-analyst install`, which fetches artifacts, writes the launchd
 * plist, and waits for healthz. If the installer is not on $PATH it prints
 * the pip install command and exits.
 *
 * Returns true iff the daemon ends up healthy. Returns false if the platform
 * is unsupported, the installer is missing, or the installer exited non-zero.
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

  const installerPath = findNanomindAnalystOnPath();
  if (installerPath === null) {
    if (!quiet) {
      process.stderr.write(
        'NanoMind-Guard daemon is not running and the installer is not on PATH.\n' +
        '\n' +
        'Install (one-time):\n' +
        '  pip install nanomind-analyst && nanomind-analyst install\n' +
        '\n' +
        'Or with pipx:\n' +
        '  pipx install nanomind-analyst && nanomind-analyst install\n' +
        '\n' +
        `Default daemon socket path: ${DEFAULT_SOCK_PATH}\n` +
        'Override with NANOMIND_GUARD_SOCK=/path/to/your.sock\n' +
        '\n' +
        'After install, verify with: hackmyagent nanomind status\n',
      );
    }
    return false;
  }

  if (!quiet) {
    process.stderr.write(
      `Found nanomind-analyst installer at ${installerPath}.\n` +
      'Running: nanomind-analyst install\n' +
      '(first run downloads ~3.4 GB of NLM weights; subsequent runs reuse the cache)\n\n',
    );
  }

  try {
    execFileSync(installerPath, ['install'], { stdio: 'inherit' });
  } catch {
    if (!quiet) {
      process.stderr.write(
        '\nnanomind-analyst install exited non-zero.\n' +
        'Re-run manually for details: nanomind-analyst install\n',
      );
    }
    return false;
  }

  // The installer exits 0 even when it failed to bring the daemon up
  // (foreign uid owns the socket, healthz timeout, launchd refusal). Its
  // stdio is inherited — a malicious or buggy installer could print
  // "success" and exit 0 without binding the socket. Re-probe healthz
  // and surface an HMA-owned diagnostic when the installer's exit code
  // disagrees with the daemon's actual state.
  const postInstallHealthy = await isDaemonHealthy();
  if (!postInstallHealthy && !quiet) {
    process.stderr.write(
      '\nnanomind-analyst exited 0 but the daemon is not responding on\n' +
      `  ${DEFAULT_SOCK_PATH}\n` +
      'Run `hackmyagent nanomind status` for diagnostics, or re-run\n' +
      '`nanomind-analyst install` to retry.\n',
    );
  }
  return postInstallHealthy;
}

/**
 * Resolve `nanomind-analyst` on PATH and check the resolved path is exec-
 * safe. Defenses:
 *   1. `/usr/bin/which` is invoked by absolute path so a hostile $PATH
 *      cannot redirect resolution of `which` itself.
 *   2. The resolved path is `realpathSync`'d, so a symlink dropped into a
 *      user-writable PATH dir cannot redirect to an attacker-controlled
 *      binary outside an accepted install prefix.
 *   3. The realpath's parent directory must not be group- or world-
 *      writable. This narrows the TOCTOU window between `which` and
 *      `execFileSync` to the same window that exists for any binary the
 *      user installed into a sane prefix (Homebrew, pipx, user-owned
 *      ~/.local/bin with 0755). Group-writable Homebrew prefixes on
 *      Intel Macs are intentionally rejected — the install message tells
 *      the user to install into a user-owned prefix.
 *
 * Returns the resolved binary path, or null when not on PATH, when which
 * exits non-zero, when realpath fails, or when the parent dir is unsafe.
 * The darwin platform gate above is the only caller, so Windows
 * `where.exe` is intentionally not handled here.
 */
function findNanomindAnalystOnPath(): string | null {
  let resolved: string;
  try {
    const out = execFileSync('/usr/bin/which', ['nanomind-analyst'], {
      stdio: ['ignore', 'pipe', 'ignore'],
    });
    resolved = out.toString('utf8').trim();
  } catch {
    return null;
  }
  if (resolved.length === 0 || !resolved.startsWith('/')) {
    return null;
  }
  let real: string;
  try {
    real = realpathSync(resolved);
  } catch {
    return null;
  }
  if (!real.startsWith('/')) {
    return null;
  }
  // Reject when the realpath's parent directory is group- or world-
  // writable: an unprivileged process there could swap the binary in the
  // TOCTOU window between this check and execFileSync. We can't close
  // the window entirely without holding a file descriptor and execing
  // it, but rejecting writable parent dirs narrows it to roots the user
  // controls (or system roots).
  try {
    const parent = dirname(real);
    const st = statSync(parent);
    // 0o022 = group-write + world-write bits.
    if ((st.mode & 0o022) !== 0) {
      return null;
    }
  } catch {
    return null;
  }
  return real;
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
 * Raw (but boundary-sanitized) per-artifact classification for the coverage
 * sweep (Phase A P1, CDS-023). Unlike runAnalystInference, this preserves the
 * daemon's universal verdict fields verbatim so the routing layer
 * (analyst-coverage.ts routeAnalystVerdict) can apply the posture-vs-attack +
 * abstention mapping itself. The shape is assignable to AnalystVerdict.
 */
export interface ArtifactCoverageVerdict {
  /** "none" | "benign" | <attack class>; "none" on the gate-bypass path. */
  attackClass: string;
  /** "benign" | "suspicious" | "malicious" | "" when absent. */
  classification: string;
  /** "critical" | "high" | "medium" | "low" | "none" | null. */
  severity: string | null;
  /** null on the gate-bypass path; the NLM's reported number otherwise. */
  confidence: number | null;
  source: 'input-classifier-gate' | 'nlm';
  /** Sanitized analysis narrative (may be empty on the gate path). */
  analysis: string;
  /** Sanitized evidence section (may be empty). */
  evidence: string;
  modelVersion: string;
  durationMs: number;
}

/**
 * Classify one artifact's content through the daemon (gate + NLM) and return
 * the universal verdict without task shaping. Returns null when the daemon is
 * absent, unhealthy, or errors — callers treat null as "analyst unavailable",
 * never as a benign verdict.
 */
export async function classifyArtifactForCoverage(
  content: string,
): Promise<ArtifactCoverageVerdict | null> {
  const startMs = Date.now();
  const response = await sendClassify(content.slice(0, MAX_INPUT_CHARS));
  if (response === null || !isClassifyOk(response)) {
    return null;
  }
  const severity = sanitizeAnalystString(response.severity).toLowerCase();
  return {
    attackClass: sanitizeAnalystString(response.predictedAttackClass),
    classification: sanitizeAnalystString(response.classification).toLowerCase(),
    severity: severity.length > 0 ? severity : null,
    confidence: typeof response.confidence === 'number' ? response.confidence : null,
    source: response.source === 'input-classifier-gate' ? 'input-classifier-gate' : 'nlm',
    analysis: sanitizeAnalystString(response.analysis),
    evidence: sanitizeAnalystString(response.evidence),
    modelVersion: `nanomind-analyst-v${MODEL_VERSION}`,
    durationMs: Date.now() - startMs,
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
