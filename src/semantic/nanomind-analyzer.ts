/**
 * NanoMind Semantic Analyzer
 *
 * Uses the local NanoMind daemon (localhost:47200) for semantic analysis
 * of skills, SOUL.md, MCP tools, and system prompts.
 *
 * Unlike the LLM analyzer (--deep flag, cloud API, costs money),
 * the NanoMind analyzer (--semantic flag) runs 100% locally with
 * zero cost per inference and zero data leaving the machine.
 *
 * Two-layer architecture:
 * 1. Static checks run first (fast, deterministic, 183 rules)
 * 2. NanoMind activates on ambiguous/NLP targets (semantic intent classification)
 */

export interface NanoMindInferRequest {
  intent: string;
  input: string;
  context?: {
    agentId?: string;
    driftScore?: number;
    declaredPurpose?: string;
  };
  priority?: 'high' | 'medium' | 'low';
}

export interface NanoMindInferResponse {
  intent: string;
  result: string;
  confidence: number;
  attackClass?: string;
  evidence?: string;
  remediation?: string;
  latencyMs: number;
  modelVersion: string;
}

export interface SemanticFinding {
  checkId: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  evidence: string[];
  confidence: number;
  attackClass?: string;
  remediation?: string;
  source: 'nanomind';
}

const DAEMON_URL = process.env.NANOMIND_URL ?? 'http://127.0.0.1:47200';

/**
 * Check if the NanoMind daemon is running.
 */
export async function isDaemonAvailable(): Promise<boolean> {
  try {
    const resp = await fetch(`${DAEMON_URL}/health`, { signal: AbortSignal.timeout(2000) });
    return resp.ok;
  } catch {
    return false;
  }
}

/**
 * Analyze a skill for malicious intent using NanoMind.
 * SCAN_SKILL_INTENT: scores the skill's instruction set for exfiltration,
 * injection, override, and persistence intent.
 */
export async function analyzeSkillIntent(skillContent: string): Promise<SemanticFinding | null> {
  const resp = await callDaemon({
    intent: 'SCAN_SKILL_INTENT',
    input: skillContent,
    priority: 'high',
  });

  if (!resp || resp.confidence < 0.5) return null;

  return {
    checkId: `SKILL-SEMANTIC-${Date.now().toString(36).slice(-4).toUpperCase()}`,
    severity: resp.confidence >= 0.85 ? 'critical' : resp.confidence >= 0.7 ? 'high' : 'medium',
    title: `Semantic Intent: ${resp.attackClass ?? resp.result}`,
    description: `NanoMind classified this skill's intent as ${resp.result} with ${(resp.confidence * 100).toFixed(0)}% confidence.`,
    evidence: resp.evidence ? [resp.evidence] : [],
    confidence: resp.confidence,
    attackClass: resp.attackClass,
    remediation: resp.remediation,
    source: 'nanomind',
  };
}

/**
 * Analyze SOUL.md governance completeness using NanoMind.
 * SCAN_SOUL_COMPLETENESS: assesses whether governance constraints
 * actually cover the attack surface.
 */
export async function analyzeSoulCompleteness(soulContent: string): Promise<SemanticFinding | null> {
  const resp = await callDaemon({
    intent: 'SCAN_SOUL_COMPLETENESS',
    input: soulContent,
    priority: 'medium',
  });

  if (!resp) return null;

  return {
    checkId: `SOUL-SEMANTIC-${Date.now().toString(36).slice(-4).toUpperCase()}`,
    severity: resp.confidence >= 0.7 ? 'high' : 'medium',
    title: 'SOUL Governance Gap Detected',
    description: `NanoMind identified governance gaps in this SOUL.md: ${resp.result}`,
    evidence: resp.evidence ? [resp.evidence] : [],
    confidence: resp.confidence,
    remediation: resp.remediation,
    source: 'nanomind',
  };
}

/**
 * Analyze MCP tool description for scope mismatches.
 * SCAN_MCP_SCOPE: detects undeclared permissions in natural language descriptions.
 */
export async function analyzeMCPScope(
  toolName: string,
  toolDescription: string,
  declaredCapabilities: string[],
): Promise<SemanticFinding | null> {
  const input = JSON.stringify({ toolName, toolDescription, declaredCapabilities });

  const resp = await callDaemon({
    intent: 'SCAN_MCP_SCOPE',
    input,
    priority: 'medium',
  });

  if (!resp || resp.confidence < 0.5) return null;

  return {
    checkId: `MCP-SEMANTIC-${Date.now().toString(36).slice(-4).toUpperCase()}`,
    severity: resp.confidence >= 0.8 ? 'high' : 'medium',
    title: `MCP Scope Mismatch: ${toolName}`,
    description: `NanoMind detected scope mismatch between tool description and declared capabilities: ${resp.result}`,
    evidence: resp.evidence ? [resp.evidence] : [],
    confidence: resp.confidence,
    attackClass: resp.attackClass,
    remediation: resp.remediation,
    source: 'nanomind',
  };
}

/**
 * Analyze system prompt behavioral envelope.
 * SCAN_PROMPT_INTENT: detects jailbreak seeds, capability creep, override risk.
 */
export async function analyzePromptIntent(promptContent: string): Promise<SemanticFinding | null> {
  const resp = await callDaemon({
    intent: 'SCAN_PROMPT_INTENT',
    input: promptContent,
    priority: 'high',
  });

  if (!resp || resp.confidence < 0.5) return null;

  return {
    checkId: `PROMPT-SEMANTIC-${Date.now().toString(36).slice(-4).toUpperCase()}`,
    severity: resp.confidence >= 0.8 ? 'critical' : resp.confidence >= 0.6 ? 'high' : 'medium',
    title: `System Prompt Risk: ${resp.attackClass ?? resp.result}`,
    description: `NanoMind analyzed the system prompt behavioral envelope: ${resp.result}`,
    evidence: resp.evidence ? [resp.evidence] : [],
    confidence: resp.confidence,
    attackClass: resp.attackClass,
    remediation: resp.remediation,
    source: 'nanomind',
  };
}

/**
 * Generate a human-readable explanation of any finding.
 * SCAN_EXPLAIN: translates machine findings into plain English.
 */
export async function explainFinding(findingJSON: string): Promise<string | null> {
  const resp = await callDaemon({
    intent: 'SCAN_EXPLAIN',
    input: findingJSON,
    priority: 'low',
  });

  return resp?.result ?? null;
}

/**
 * Internal: call the NanoMind daemon.
 */
async function callDaemon(req: NanoMindInferRequest): Promise<NanoMindInferResponse | null> {
  try {
    const resp = await fetch(`${DAEMON_URL}/v1/infer`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req),
      signal: AbortSignal.timeout(1200), // 1.2s timeout per brief spec
    });

    if (!resp.ok) return null;
    return await resp.json() as NanoMindInferResponse;
  } catch {
    return null; // daemon unavailable or timeout -- fail gracefully
  }
}
