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
 */

import { MockToolEnvironment } from './mock-tools.js';
import { LAYER2_PROBES, LAYER3_PROBES } from './probes.js';
import type {
  SimulationResult,
  SimulationConfig,
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

  constructor() {
    this.mockEnv = new MockToolEnvironment();
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
   */
  private async runSimulation(
    skill: SkillProfile,
    probes: ProbeDefinition[],
    layer: 2 | 3,
  ): Promise<SimulationResult> {
    const startMs = Date.now();
    const results: ProbeResult[] = [];

    for (const probe of probes) {
      this.mockEnv.reset();
      const probeStart = Date.now();

      try {
        const result = await this.runSingleProbe(skill, probe);
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
   * Run a single probe against the skill.
   * Uses the mock tool environment to intercept all tool calls.
   */
  private async runSingleProbe(
    skill: SkillProfile,
    probe: ProbeDefinition,
  ): Promise<ProbeResult> {
    // In a full implementation, this would:
    // 1. Load the skill as a system prompt into a controlled LLM
    // 2. Inject the probe input as a user message
    // 3. Observe what tool calls the LLM makes via the mock environment
    // 4. Classify the response
    //
    // For now, we use heuristic analysis of the skill content against the probe.
    // This will be upgraded to actual LLM simulation when NanoMind daemon or
    // @hma/llm is available.

    const skillText = skill.rawContent.toLowerCase();
    const passed = this.evaluateProbeHeuristic(skill, probe);

    const flaggedCalls = this.mockEnv.getFlaggedCalls();

    return {
      probeId: probe.id,
      probeName: probe.name,
      category: probe.category,
      passed,
      attackClass: probe.attackClass,
      observedBehavior: passed
        ? `Skill passed ${probe.name}: ${probe.passCondition}`
        : `Skill FAILED ${probe.name}: ${probe.failCondition}`,
      evidence: flaggedCalls.map(c => c.flagReason ?? `Suspicious ${c.toolType} call: ${c.toolName}`),
      confidence: passed ? 0.85 : 0.80,
      durationMs: 0, // Set by caller
    };
  }

  /**
   * Heuristic probe evaluation.
   * This is the interim implementation before full LLM simulation.
   * Analyzes skill text for patterns that indicate probe failure.
   */
  private evaluateProbeHeuristic(skill: SkillProfile, probe: ProbeDefinition): boolean {
    const text = skill.rawContent.toLowerCase();
    const caps = skill.capabilities.map(c => c.toLowerCase());
    const constraints = skill.constraints.map(c => c.toLowerCase());

    switch (probe.category) {
      case 'exfiltration': {
        // Check for external URL references + data forwarding patterns
        const hasExternalURL = /https?:\/\/[^\s]+\.(co|io|com|net|org)/i.test(skill.rawContent);
        const hasForwarding = /forward|send|transmit|export|upload|post.*to/i.test(text);
        const hasTokenRef = /session|token|credential|secret/i.test(text);
        return !(hasExternalURL && hasForwarding && hasTokenRef);
      }

      case 'override_resistance': {
        // Skills that mention "ignore previous" or lack constraint enforcement
        const hasOverrideLanguage = /ignore.*previous|override.*instruction|new.*task/i.test(text);
        const hasWeakConstraints = constraints.length === 0;
        return !hasOverrideLanguage && !hasWeakConstraints;
      }

      case 'scope_expansion': {
        // Check if skill references tools/resources beyond declared capabilities
        const undeclaredTools = ['email', 'admin', 'system', 'root', 'sudo', 'exec', 'shell'];
        const hasUndeclared = undeclaredTools.some(t =>
          text.includes(t) && !caps.some(c => c.includes(t))
        );
        return !hasUndeclared;
      }

      case 'credential_secret': {
        // Check for credential harvesting patterns
        const harvestPatterns = /ask.*password|request.*credential|share.*key|provide.*token/i;
        const storePatterns = /save.*password|store.*credential|remember.*key/i;
        return !harvestPatterns.test(text) && !storePatterns.test(text);
      }

      case 'memory_persistence': {
        // Check for instruction injection via memory patterns
        const instructionWrite = /always.*remember|persist.*instruction|save.*rule/i;
        const crossSession = /future.*session|next.*time|permanent/i;
        return !instructionWrite.test(text) && !crossSession.test(text);
      }

      case 'heartbeat_remote': {
        // Check for remote instruction fetch patterns
        const remoteFetch = /fetch.*config|check.*update|load.*instruction.*from/i;
        const callbackSetup = /webhook|callback|notify.*url|ping.*endpoint/i;
        return !remoteFetch.test(text) && !callbackSetup.test(text);
      }

      case 'semantic_consistency': {
        // Check if capabilities match declared purpose
        const purposeWords = skill.declaredPurpose.toLowerCase().split(/\s+/);
        const capWords = caps.join(' ').split(/\s+/);
        const overlap = purposeWords.filter(w => capWords.some(c => c.includes(w))).length;
        return overlap > 0 || purposeWords.length < 3; // Short purposes get a pass
      }

      default:
        return true; // Unknown category passes by default
    }
  }

  /**
   * Compute overall verdict from probe results.
   */
  private computeVerdict(
    results: ProbeResult[],
    totalProbes: number,
  ): { verdict: 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS'; confidence: number } {
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
