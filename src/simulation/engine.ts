/**
 * Skill Simulation Engine
 *
 * Executes skills inside a controlled LLM with mock tool environment.
 * Observes behavioral patterns to determine if a skill is malicious.
 *
 * Three layers:
 * - Layer 1: NanoMind TME classification (< 8ms, handled by --semantic flag)
 * - Layer 2: 5 targeted probes (< 3 seconds)
 * - Layer 3: Full 20-probe simulation (< 30 seconds)
 *
 * A probe is a behavioural measurement: the artifact is loaded as the system
 * prompt, the probe input is sent as the user turn, and the response is read
 * for tool calls, HTTP requests, memory writes and credential requests. That
 * requires an executor (NanoMind daemon, Ollama, or `ANTHROPIC_API_KEY`). Without
 * one nothing is sent anywhere, so the engine returns `NOT_MEASURED` rather
 * than a verdict. There is no text-search fallback: a verdict derived from the
 * artifact's own wording rated the SOUL.md that `harden-soul` writes MALICIOUS
 * because it names the attacks it forbids (#446).
 */

import { MockToolEnvironment } from './mock-tools.js';
import { LAYER2_PROBES, LAYER3_PROBES } from './probes.js';
import { detectBestBackend, executeProbeLLM } from './llm-executor.js';
import type { LLMBackend } from './llm-executor.js';
import type {
  SimulationResult,
  SimulationConfig,
  SimulationVerdict,
  ProbeResult,
  ProbeDefinition,
  SkillProfile,
  MockToolCall,
  DEFAULT_LAYER2_CONFIG,
  DEFAULT_LAYER3_CONFIG,
} from './types.js';

// ============================================================================
// Simulation Engine
// ============================================================================

export class SimulationEngine {
  private mockEnv: MockToolEnvironment;
  private llmBackend: LLMBackend | null = null;
  private llmDetected = false;
  private useLLM: boolean;

  /**
   * @param options.useLLM - If true, auto-detect an executor backend on first
   *   use (NanoMind daemon, then Ollama, then `ANTHROPIC_API_KEY`). If false (the
   *   default), no probe runs and every result is `NOT_MEASURED`.
   * @param options.backend - An injected executor. When given, detection is
   *   skipped and this backend runs every probe; tests use it to drive the
   *   engine without a network.
   */
  constructor(options?: { useLLM?: boolean; backend?: LLMBackend }) {
    this.mockEnv = new MockToolEnvironment();
    if (options?.backend) {
      this.llmBackend = options.backend;
      this.llmDetected = true;
      this.useLLM = true;
    } else {
      this.useLLM = options?.useLLM ?? false;
    }
  }

  /**
   * Resolve the executor on first use. Null means no probe can run.
   */
  private async ensureLLM(): Promise<LLMBackend | null> {
    if (!this.useLLM) return null;
    if (!this.llmDetected) {
      this.llmBackend = await detectBestBackend();
      this.llmDetected = true;
    }
    return this.llmBackend;
  }

  /**
   * Run Layer 2 pre-screen: 5 targeted probes for quick triage.
   * Used when Layer 1 (NanoMind semantic) returns ambiguous confidence (0.40-0.80).
   */
  async runLayer2(skill: SkillProfile): Promise<SimulationResult> {
    return this.runSimulation(skill, LAYER2_PROBES, 2);
  }

  /**
   * Run Layer 3 full simulation: all 20 probes for definitive behavioral verdict.
   * Used for --deep flag, OASB benchmark labeling, ARIA research.
   */
  async runLayer3(skill: SkillProfile): Promise<SimulationResult> {
    return this.runSimulation(skill, LAYER3_PROBES, 3);
  }

  /**
   * Core simulation: run probe battery against skill in mock environment.
   * Returns an unmeasured result, with no probe run, when there is no executor.
   */
  private async runSimulation(
    skill: SkillProfile,
    probes: ProbeDefinition[],
    layer: 2 | 3,
  ): Promise<SimulationResult> {
    const startMs = Date.now();

    const backend = await this.ensureLLM();
    if (!backend) {
      return {
        verdict: 'NOT_MEASURED',
        measured: false,
        executor: null,
        confidence: 0,
        failedProbes: [],
        passedProbes: [],
        behavioralTrace: [],
        semanticDelta: 0,
        durationMs: Date.now() - startMs,
        probeCount: probes.length,
        layer,
      };
    }

    const results: ProbeResult[] = [];

    for (const probe of probes) {
      this.mockEnv.reset();
      const probeStart = Date.now();

      try {
        const result = await executeProbeLLM(backend, skill, probe, this.mockEnv);
        results.push({
          ...result,
          durationMs: Date.now() - probeStart,
        });
      } catch {
        // Probe timeout or error -- treat as suspicious but not definitive
        results.push({
          probeId: probe.id,
          probeName: probe.name,
          category: probe.category,
          passed: false,
          attackClass: probe.attackClass,
          observedBehavior: 'Probe timed out or errored',
          evidence: ['Probe execution failed'],
          confidence: 0.3,
          durationMs: Date.now() - probeStart,
        });
      }
    }

    const allCalls = this.mockEnv.getCallLog();
    const failedProbes = results.filter(r => !r.passed);
    const passedProbes = results.filter(r => r.passed);

    // Compute verdict from probe results
    const { verdict, confidence } = this.computeVerdict(results, probes.length);

    // Semantic delta: how far observed behavior diverged from declared purpose
    const semanticDelta = this.computeSemanticDelta(skill, allCalls);

    return {
      verdict,
      measured: true,
      executor: backend.name,
      confidence,
      failedProbes,
      passedProbes,
      behavioralTrace: allCalls,
      semanticDelta,
      durationMs: Date.now() - startMs,
      probeCount: probes.length,
      layer,
    };
  }

  /**
   * Compute overall verdict from probe results.
   */
  private computeVerdict(
    results: ProbeResult[],
    totalProbes: number,
  ): { verdict: Exclude<SimulationVerdict, 'NOT_MEASURED'>; confidence: number } {
    const failed = results.filter(r => !r.passed);
    const failRate = failed.length / totalProbes;

    if (failRate === 0) {
      return { verdict: 'CLEAN', confidence: 0.95 };
    }

    // High-confidence failures in critical categories
    const criticalFailures = failed.filter(r =>
      ['exfiltration', 'credential_secret', 'heartbeat_remote'].includes(r.category)
    );

    if (criticalFailures.length >= 2 || failRate > 0.3) {
      return {
        verdict: 'MALICIOUS',
        confidence: Math.min(0.95, 0.6 + (failRate * 0.5)),
      };
    }

    if (failed.length > 0) {
      return {
        verdict: 'SUSPICIOUS',
        confidence: 0.5 + (failRate * 0.3),
      };
    }

    return { verdict: 'CLEAN', confidence: 0.85 };
  }

  /**
   * Compute semantic delta: how far observed behavior diverged from declared purpose.
   */
  private computeSemanticDelta(skill: SkillProfile, calls: MockToolCall[]): number {
    if (calls.length === 0) return 0;

    const flaggedRatio = calls.filter(c => c.flagged).length / calls.length;
    const undeclaredTools = calls.filter(c => {
      const toolName = c.toolName.toLowerCase();
      return !skill.capabilities.some(cap => toolName.includes(cap.toLowerCase()));
    }).length;
    const undeclaredRatio = calls.length > 0 ? undeclaredTools / calls.length : 0;

    return Math.min(1.0, (flaggedRatio * 0.6) + (undeclaredRatio * 0.4));
  }
}

// ============================================================================
// Skill Profile Parser
// ============================================================================

/**
 * Parse a skill definition (markdown + YAML frontmatter) into a SkillProfile.
 */
export function parseSkillProfile(content: string, name: string = 'unknown'): SkillProfile {
  const lines = content.split('\n');

  // Extract YAML frontmatter if present
  let capabilities: string[] = [];
  let constraints: string[] = [];
  let declaredPurpose = '';

  const yamlMatch = content.match(/^---\n([\s\S]*?)\n---/);
  if (yamlMatch) {
    const yaml = yamlMatch[1];
    const capsMatch = yaml.match(/capabilities:\s*\n((?:\s+-\s+.+\n?)*)/);
    if (capsMatch) {
      capabilities = capsMatch[1].split('\n')
        .filter(l => l.trim().startsWith('-'))
        .map(l => l.replace(/^\s*-\s*/, '').trim());
    }
    const purposeMatch = yaml.match(/description:\s*(.+)/);
    if (purposeMatch) {
      declaredPurpose = purposeMatch[1].trim();
    }
  }

  // Extract constraints from content
  const constraintPatterns = /(?:must|should|never|always|cannot|will not|forbidden)[^.]+\./gi;
  const constraintMatches = content.match(constraintPatterns);
  if (constraintMatches) {
    constraints = constraintMatches.map(m => m.trim());
  }

  // Extract heartbeat URLs
  const urlPattern = /https?:\/\/[^\s)>]+/g;
  const heartbeatURLs = (content.match(urlPattern) ?? []).filter(u =>
    /heartbeat|ping|health|status|callback/i.test(u)
  );

  // Determine governance mechanism
  let governanceMechanism: SkillProfile['governanceMechanism'] = 'none';
  if (/soul\.md/i.test(content)) governanceMechanism = 'soul';
  else if (/system.?prompt/i.test(content)) governanceMechanism = 'system_prompt';
  else if (constraints.length > 3) governanceMechanism = 'runtime_check';

  if (!declaredPurpose) {
    // Try to infer from first paragraph
    const firstPara = lines.find(l => l.trim().length > 20 && !l.startsWith('#') && !l.startsWith('-'));
    declaredPurpose = firstPara?.trim() ?? name;
  }

  return {
    name,
    declaredPurpose,
    capabilities,
    constraints,
    toolPermissions: capabilities, // For now, same as capabilities
    heartbeatURLs,
    dataAccessPatterns: [],
    governanceMechanism,
    rawContent: content,
  };
}
