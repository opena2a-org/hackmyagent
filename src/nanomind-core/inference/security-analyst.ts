/**
 * NanoMind Security Analyst -- Generative model inference
 *
 * Runs the nanomind-security-analyst model (SmolLM2-1.7B 12L SFT)
 * for structured security analysis. This is a GENERATIVE model that
 * produces JSON output, NOT a replacement for the TME classifier.
 *
 * Two inference backends (auto-detected):
 *   1. MLX (mlx_lm)     -- Apple Silicon only, safetensors (1.8GB)
 *   2. llama.cpp         -- Cross-platform, GGUF Q4_K_M (~1GB) [planned]
 *
 * Task types:
 *   - threatAnalysis, credentialContextClassification, falsePositiveDetection,
 *     artifactClassification, checkExplanation, governanceReasoning, intelReport
 *
 * Gated behind --analm flag. Model downloaded on-demand via `analm setup`.
 */

import { join } from 'node:path';
import { homedir } from 'node:os';
import { execFile } from 'node:child_process';

// ============================================================================
// Types
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

export type AnalystBackend = 'mlx' | 'llamacpp' | 'none';

export interface AnalystStatus {
  available: boolean;
  backend: AnalystBackend;
  modelCached: boolean;
  platform: string;
  setupCommand: string;
}

// ============================================================================
// Constants
// ============================================================================

const HF_REPO = 'opena2a/nanomind-security-analyst';
const MODEL_VERSION = '0.1.0';

/** Maximum input length sent to the analyst (tokens are ~4 chars avg) */
const MAX_INPUT_CHARS = 2048;

/** Inference timeout. The 1.7B model runs ~2-5s per request on M-series. */
const INFERENCE_TIMEOUT_MS = 30_000;

// ============================================================================
// Backend Detection
// ============================================================================

let _detectedBackend: AnalystBackend | undefined;
let _modelCached: boolean | undefined;

/**
 * Detect the best available inference backend.
 * MLX is preferred (Apple Silicon), llama.cpp is cross-platform fallback.
 */
async function detectBackend(): Promise<AnalystBackend> {
  if (_detectedBackend !== undefined) return _detectedBackend;

  // Try MLX (Apple Silicon only)
  if (process.platform === 'darwin') {
    try {
      await execAsync('uv', [
        'run', '--with', 'mlx-lm', 'python3', '-c',
        'import mlx_lm; print("ok")',
      ], { timeout: 15_000 });
      _detectedBackend = 'mlx';
      return _detectedBackend;
    } catch {
      // MLX not available, try llama.cpp
    }
  }

  // Try llama.cpp (cross-platform) -- planned for future release
  // When implemented, check for llama-cpp-python or llamafile binary
  // try {
  //   await execAsync('uv', [
  //     'run', '--with', 'llama-cpp-python', 'python3', '-c',
  //     'from llama_cpp import Llama; print("ok")',
  //   ], { timeout: 15_000 });
  //   _detectedBackend = 'llamacpp';
  //   return _detectedBackend;
  // } catch { /* not available */ }

  _detectedBackend = 'none';
  return _detectedBackend;
}

/**
 * Check if the model is already cached locally.
 */
async function isModelCached(): Promise<boolean> {
  if (_modelCached !== undefined) return _modelCached;

  try {
    const checkScript = `
from huggingface_hub import try_to_load_from_cache
import json
path = try_to_load_from_cache("${HF_REPO}", "config.json")
print(json.dumps({"cached": path is not None}))
`;
    const result = await execAsync('uv', [
      'run', '--with', 'huggingface-hub', 'python3', '-c', checkScript,
    ], { timeout: 10_000 });
    const parsed = JSON.parse(result.stdout.trim());
    _modelCached = Boolean(parsed.cached);
  } catch {
    _modelCached = false;
  }

  return _modelCached;
}

/**
 * Get the full status of the analyst subsystem.
 * Used by `analyst status` and scan hints.
 */
export async function getAnalystStatus(): Promise<AnalystStatus> {
  const backend = await detectBackend();
  const cached = backend !== 'none' ? await isModelCached() : false;

  return {
    available: backend !== 'none' && cached,
    backend,
    modelCached: cached,
    platform: process.platform === 'darwin' ? 'Apple Silicon (MLX)' : process.platform,
    setupCommand: 'hackmyagent analm setup',
  };
}

/**
 * Quick check: is the analyst ready to run right now?
 * Does NOT trigger downloads. Used by orchestrator to decide whether
 * to show the "run analyst setup" hint.
 */
export async function isAnalystReady(): Promise<boolean> {
  const backend = await detectBackend();
  if (backend === 'none') return false;
  return isModelCached();
}

// ============================================================================
// Model Setup
// ============================================================================

/**
 * Download the AnaLM model. Called by `analm setup` command.
 * Returns true on success.
 */
export async function setupAnalystModel(quiet = false): Promise<boolean> {
  const backend = await detectBackend();

  if (backend === 'none') {
    if (!quiet) {
      process.stderr.write(
        'No supported inference backend found.\n' +
        (process.platform === 'darwin'
          ? 'Install uv (https://docs.astral.sh/uv/) and run again.\n'
          : 'Cross-platform support (llama.cpp) coming soon.\n' +
            'Currently requires Apple Silicon Mac with MLX.\n'),
      );
    }
    return false;
  }

  if (await isModelCached()) {
    if (!quiet) process.stderr.write('AnaLM model already downloaded.\n');
    return true;
  }

  if (!quiet) {
    process.stderr.write(
      `Downloading AnaLM v${MODEL_VERSION} ` +
      `(${backend === 'mlx' ? '1.8GB safetensors' : '~1GB GGUF'})...\n`,
    );
  }

  try {
    const downloadScript = `
from huggingface_hub import snapshot_download
import json
path = snapshot_download("${HF_REPO}")
print(json.dumps({"status": "ok", "path": path}))
`;
    const result = await execAsync('uv', [
      'run', '--with', 'huggingface-hub', 'python3', '-c', downloadScript,
    ], { timeout: 600_000 }); // 10 min for large model

    const parsed = JSON.parse(result.stdout.trim());
    if (parsed.status === 'ok') {
      _modelCached = true;
      if (!quiet) {
        process.stderr.write('AnaLM model ready.\n');
        process.stderr.write('Use --analm with any scan command for AI-powered analysis.\n');
      }
      return true;
    }
  } catch (err: any) {
    if (!quiet) {
      process.stderr.write(
        `Download failed: ${err?.message ?? 'unknown error'}\n` +
        'Check your network connection and try again.\n',
      );
    }
  }

  return false;
}

// ============================================================================
// Inference
// ============================================================================

/**
 * Run analyst inference on the given request.
 * Returns null if the analyst is unavailable or inference fails.
 * Caller must gate behind --analyze flag.
 */
export async function runAnalystInference(
  request: AnalystRequest,
): Promise<AnalystResponse | null> {
  const backend = await detectBackend();
  if (backend === 'none') return null;

  const cached = await isModelCached();
  if (!cached) return null;

  if (backend === 'mlx') {
    return runMlxInference(request);
  }

  // llamacpp backend -- planned
  return null;
}

async function runMlxInference(request: AnalystRequest): Promise<AnalystResponse | null> {
  const startMs = Date.now();

  const truncatedContent = request.content.slice(0, MAX_INPUT_CHARS);
  const systemPrompt = getSystemPrompt(request.taskType);
  const userMessage = request.context
    ? `Context: ${request.context}\n\nContent:\n${truncatedContent}`
    : truncatedContent;

  // Escape for safe embedding in Python string
  const escapedSystem = JSON.stringify(systemPrompt);
  const escapedUser = JSON.stringify(userMessage);

  const inferenceScript = `
import json, sys, re
from mlx_lm import load, generate

model, tokenizer = load("${HF_REPO}")

messages = [
    {"role": "system", "content": ${escapedSystem}},
    {"role": "user", "content": ${escapedUser}},
]

prompt = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
response = generate(model, tokenizer, prompt=prompt, max_tokens=512, verbose=False)

# Extract JSON from response
try:
    parsed = json.loads(response)
    print(json.dumps({"ok": True, "result": parsed}))
except json.JSONDecodeError:
    match = re.search(r'\\{[^{}]*(?:\\{[^{}]*\\}[^{}]*)*\\}', response, re.DOTALL)
    if match:
        try:
            parsed = json.loads(match.group())
            print(json.dumps({"ok": True, "result": parsed}))
        except json.JSONDecodeError:
            print(json.dumps({"ok": False, "raw": response[:500]}))
    else:
        print(json.dumps({"ok": False, "raw": response[:500]}))
`;

  try {
    const result = await execAsync('uv', [
      'run', '--with', 'mlx-lm', 'python3', '-c', inferenceScript,
    ], { timeout: INFERENCE_TIMEOUT_MS });

    const parsed = JSON.parse(result.stdout.trim());
    const durationMs = Date.now() - startMs;

    if (parsed.ok && parsed.result) {
      return {
        taskType: request.taskType,
        result: parsed.result,
        confidence: typeof parsed.result.confidence === 'number' ? parsed.result.confidence : 0.5,
        modelVersion: `nanomind-analyst-v${MODEL_VERSION}`,
        durationMs,
        backend: 'mlx',
      };
    }

    return null;
  } catch {
    return null;
  }
}

// ============================================================================
// Task-Specific Runners
// ============================================================================

/**
 * Run threat analysis on content flagged as suspicious/malicious.
 */
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
    attackVector: String(r.attackVector ?? attackClass),
    description: String(r.description ?? ''),
    mitigations: Array.isArray(r.mitigations) ? r.mitigations.map(String) : [],
    confidence: response.confidence,
  };
}

/**
 * Assess whether a credential finding is a real credential or test/example.
 */
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
  const classification = validClasses.includes(r.classification as any)
    ? (r.classification as CredentialContext['classification'])
    : 'unknown';

  return {
    classification,
    reasoning: String(r.reasoning ?? ''),
    confidence: response.confidence,
  };
}

/**
 * Assess whether a finding is a false positive.
 */
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

/**
 * Generate an intelligence report summarizing scan findings.
 */
export async function generateIntelReport(
  findingsSummary: string,
): Promise<AnalystResponse | null> {
  return runAnalystInference({
    taskType: 'intelReport',
    content: findingsSummary,
  });
}

// ============================================================================
// System Prompts
// ============================================================================

function getSystemPrompt(taskType: AnalystTaskType): string {
  const prompts: Record<AnalystTaskType, string> = {
    threatAnalysis:
      'You are a security analyst. Analyze the given content for threats. ' +
      'Respond with JSON: {"threatLevel": "critical|high|medium|low|none", ' +
      '"attackVector": "string", "description": "string", "mitigations": ["string"], ' +
      '"confidence": 0.0-1.0}',
    credentialContextClassification:
      'You are a credential context classifier. Determine if the credential in the content ' +
      'is real, test, example, or placeholder. ' +
      'Respond with JSON: {"classification": "real|test|example|placeholder|unknown", ' +
      '"reasoning": "string", "confidence": 0.0-1.0}',
    falsePositiveDetection:
      'You are a false positive detector for security findings. ' +
      'Determine if the described finding is a false positive based on the content. ' +
      'Respond with JSON: {"isFalsePositive": true|false, "reasoning": "string", ' +
      '"confidence": 0.0-1.0}',
    artifactClassification:
      'You are a security artifact classifier. Classify the type of the given artifact. ' +
      'Respond with JSON: {"artifactType": "string", "reasoning": "string", ' +
      '"confidence": 0.0-1.0}',
    checkExplanation:
      'You are a security check explainer. Explain what the security check found and why it matters. ' +
      'Respond with JSON: {"explanation": "string", "impact": "string", ' +
      '"recommendation": "string", "confidence": 0.0-1.0}',
    governanceReasoning:
      'You are a governance analyst. Analyze the governance posture of the given artifact. ' +
      'Respond with JSON: {"gaps": ["string"], "strengths": ["string"], ' +
      '"recommendations": ["string"], "confidence": 0.0-1.0}',
    intelReport:
      'You are a security intelligence analyst. Generate an intelligence report for the scan results. ' +
      'Respond with JSON: {"summary": "string", "keyFindings": ["string"], ' +
      '"riskAssessment": "string", "recommendations": ["string"], "confidence": 0.0-1.0}',
  };

  return prompts[taskType];
}

// ============================================================================
// Subprocess Helper
// ============================================================================

function execAsync(
  cmd: string,
  args: string[],
  options: { timeout?: number } = {},
): Promise<{ stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, {
      timeout: options.timeout ?? 30_000,
      maxBuffer: 10 * 1024 * 1024, // 10MB
      env: {
        ...process.env,
        HF_HOME: join(homedir(), '.cache', 'huggingface'),
      },
    }, (error, stdout, stderr) => {
      if (error) {
        reject(error);
      } else {
        resolve({ stdout: String(stdout), stderr: String(stderr) });
      }
    });
  });
}
