import type {
  ARPEvent,
  ARPConfig,
  IntelligenceConfig,
  LLMAdapter,
  LLMAssessment,
  EventSeverity,
} from '../types';
import { BudgetController } from './budget';
import { autoDetectAdapter, createAdapter } from './adapters';
import { AnomalyDetector } from './anomaly';
import { hasFeature, PREMIUM_FEATURES } from '../license';

const SEVERITY_ORDER: EventSeverity[] = ['info', 'low', 'medium', 'high', 'critical'];

/**
 * The 3-Layer Intelligence Coordinator.
 *
 * L0: Rules (free)      — Pattern matching, allowlists, thresholds. Every event.
 * L1: Statistical (free) — Z-score anomaly detection, baseline deviation. L0 flags.
 * L2: LLM-Assisted ($)   — Micro-prompt to agent's LLM. Only L1 flags + budget check.
 *
 * 99% of events never reach L2. Cost is ~$0.01/day for most agents.
 */
export class IntelligenceCoordinator {
  private readonly config: IntelligenceConfig;
  private readonly agentContext: string;
  private readonly budget: BudgetController;
  private readonly anomaly: AnomalyDetector;
  private adapter: LLMAdapter | null = null;
  private batchQueue: ARPEvent[] = [];
  private batchTimer?: ReturnType<typeof setTimeout>;

  constructor(arpConfig: ARPConfig, dataDir: string) {
    this.config = arpConfig.intelligence ?? {};
    this.budget = new BudgetController(dataDir, this.config);
    this.anomaly = new AnomalyDetector();

    // Build agent context for LLM prompts
    this.agentContext = buildAgentContext(arpConfig);

    // Initialize LLM adapter if intelligence is enabled
    if (this.config.enabled !== false) {
      try {
        if (this.config.adapter) {
          this.adapter = createAdapter(this.config.adapter, this.config.adapterConfig);
        } else {
          this.adapter = autoDetectAdapter(this.config.adapterConfig);
        }
      } catch {
        // No adapter available — L2 disabled, L0+L1 still work
        this.adapter = null;
      }
    }
  }

  /**
   * Analyze an event through the 3-layer stack.
   * Mutates the event's category, severity, and classifiedBy fields.
   * Returns the LLM assessment if L2 was invoked.
   */
  async analyze(event: ARPEvent): Promise<LLMAssessment | null> {
    // L0: Already classified by the monitor that emitted it

    // L1: Statistical anomaly detection (free)
    const anomalyScore = this.anomaly.score(event);
    if (anomalyScore > 2.0) {
      // Z-score > 2 standard deviations — flag as anomaly
      if (event.category === 'normal') {
        event.category = 'anomaly';
      }
      if (severityIndex(event.severity) < severityIndex('medium')) {
        event.severity = 'medium';
      }
      event.classifiedBy = 'L1-statistical';
    }

    // L1 records this event for future baseline
    this.anomaly.record(event);

    // L2: LLM assessment (only if L1 flagged and budget allows)
    if (this.shouldEscalateToL2(event)) {
      // AI-layer L2 assessment requires premium license
      if (AI_LAYER_SOURCES.has(event.source)) {
        const licensed = await hasFeature(PREMIUM_FEATURES.AI_LAYER_L2);
        if (!licensed) return null;
      }

      if (this.config.enableBatching && event.severity !== 'critical') {
        return this.queueForBatch(event);
      }
      return this.assessWithLlm(event);
    }

    return null;
  }

  /** Get budget status */
  getBudgetStatus() {
    return this.budget.getStatus();
  }

  /** Stop the coordinator (flush batches, clean up) */
  async stop(): Promise<void> {
    if (this.batchTimer) {
      clearTimeout(this.batchTimer);
      this.batchTimer = undefined;
    }
    // Flush remaining batch
    if (this.batchQueue.length > 0) {
      await this.flushBatch();
    }
  }

  private shouldEscalateToL2(event: ARPEvent): boolean {
    // L2 disabled
    if (this.config.enabled === false) return false;
    if (!this.adapter) return false;

    // Only escalate if L1 flagged it
    if (event.category === 'normal') return false;

    // Minimum severity check
    const minSev = this.config.minSeverityForLlm ?? 'medium';
    if (severityIndex(event.severity) < severityIndex(minSev)) return false;

    // Budget check
    const estimatedCost = this.adapter.estimateCost(
      200, // ~200 input tokens for micro-prompt
      this.config.maxTokensPerCall ?? 300,
    );
    if (!this.budget.canAfford(estimatedCost)) return false;

    return true;
  }

  private async assessWithLlm(event: ARPEvent): Promise<LLMAssessment | null> {
    if (!this.adapter) return null;

    const prompt = buildMicroPrompt(this.agentContext, event);
    const maxTokens = this.config.maxTokensPerCall ?? 300;

    try {
      const response = await this.adapter.assess(prompt, maxTokens);
      const cost = this.adapter.estimateCost(response.inputTokens, response.outputTokens);

      this.budget.record(cost, response.inputTokens + response.outputTokens);

      const assessment = parseAssessment(response.content, response.inputTokens + response.outputTokens, cost);

      event.llmAssessment = assessment;
      event.classifiedBy = 'L2-llm';

      // LLM can upgrade severity
      if (assessment.recommendation === 'kill') {
        event.severity = 'critical';
        event.category = 'threat';
      } else if (assessment.recommendation === 'pause') {
        event.severity = 'high';
        event.category = 'violation';
      }

      return assessment;
    } catch {
      // LLM failure — fall back to L1 classification
      return null;
    }
  }

  private queueForBatch(event: ARPEvent): null {
    this.batchQueue.push(event);

    if (!this.batchTimer) {
      const windowMs = this.config.batchWindowMs ?? 300000;
      this.batchTimer = setTimeout(() => {
        this.flushBatch().catch(() => {});
        this.batchTimer = undefined;
      }, windowMs);

      if (this.batchTimer.unref) {
        this.batchTimer.unref();
      }
    }

    return null; // Assessment will come later
  }

  private async flushBatch(): Promise<void> {
    if (this.batchQueue.length === 0 || !this.adapter) return;

    const events = this.batchQueue.splice(0);
    const prompt = buildBatchPrompt(this.agentContext, events);
    const maxTokens = Math.min((this.config.maxTokensPerCall ?? 300) * 2, 1000);

    try {
      const response = await this.adapter.assess(prompt, maxTokens);
      const cost = this.adapter.estimateCost(response.inputTokens, response.outputTokens);
      this.budget.record(cost, response.inputTokens + response.outputTokens);
    } catch {
      // Batch failure — events remain at L1 classification
    }
  }
}

// --- Prompt Engineering (the craft) ---

function buildAgentContext(config: ARPConfig): string {
  const parts = [`Agent: ${config.agentName}`];
  if (config.agentDescription) {
    parts.push(`Purpose: ${config.agentDescription}`);
  }
  if (config.declaredCapabilities?.length) {
    parts.push(`Capabilities: ${config.declaredCapabilities.join(', ')}`);
  }
  return parts.join('\n');
}

/** AI-layer monitor sources that use specialized prompts */
const AI_LAYER_SOURCES = new Set(['prompt', 'mcp-protocol', 'a2a-protocol']);

/**
 * Micro-prompt: ~200 tokens in, ~100 tokens out.
 * Designed for speed and cost efficiency. No chain-of-thought.
 * Uses specialized templates for AI-layer threats.
 */
function buildMicroPrompt(agentContext: string, event: ARPEvent): string {
  if (AI_LAYER_SOURCES.has(event.source)) {
    return buildAILayerPrompt(agentContext, event);
  }

  return `SECURITY ASSESSMENT — answer concisely.

${agentContext}

Event: ${event.source} monitor detected ${event.category} (${event.severity})
Detail: ${event.description}
Data: ${JSON.stringify(event.data).slice(0, 500)}

Is this behavior consistent with the agent's declared purpose and capabilities?
Respond in exactly this format:
CONSISTENT: YES or NO
CONFIDENCE: 0.0-1.0
REASONING: one sentence
ACTION: ALLOW, ALERT, PAUSE, or KILL`;
}

/**
 * Specialized prompt for AI-layer threats (prompt injection, MCP exploitation, A2A spoofing).
 * Provides the LLM with pattern match context for true/false positive assessment.
 */
function buildAILayerPrompt(agentContext: string, event: ARPEvent): string {
  const data = event.data;
  const patternId = data.patternId ?? 'unknown';
  const patternCategory = data.patternCategory ?? event.source;
  const matchedText = data.matchedText ?? '';
  const direction = data.direction ?? '';

  let contentContext = '';
  if (event.source === 'prompt') {
    contentContext = direction === 'input'
      ? `User/agent sent input that matched pattern ${patternId} (${patternCategory}).`
      : `LLM response matched output leak pattern ${patternId} (${patternCategory}).`;
  } else if (event.source === 'mcp-protocol') {
    const toolName = data.toolName ?? 'unknown';
    contentContext = `MCP tool call "${toolName}" has parameters matching exploitation pattern ${patternId}.`;
  } else if (event.source === 'a2a-protocol') {
    const from = data.from ?? 'unknown';
    const to = data.to ?? 'unknown';
    contentContext = `A2A message from "${from}" to "${to}" matched attack pattern ${patternId}.`;
  }

  return `AI-LAYER THREAT ASSESSMENT — determine if this is a true positive or false positive.

${agentContext}

Detection: ${event.description}
Context: ${contentContext}
Matched text: "${String(matchedText).slice(0, 300)}"
Pattern: ${patternId} — ${patternCategory}
Severity: ${event.severity}

Could this be legitimate usage given the agent's purpose, or is this a genuine attack attempt?
Consider: obfuscation techniques, benign edge cases, and the agent's declared capabilities.

Respond in exactly this format:
CONSISTENT: YES (benign/false positive) or NO (genuine threat)
CONFIDENCE: 0.0-1.0
REASONING: one sentence explaining why
ACTION: ALLOW, ALERT, PAUSE, or KILL`;
}

function buildBatchPrompt(agentContext: string, events: ARPEvent[]): string {
  const summary = events.map((e, i) =>
    `${i + 1}. [${e.source}] ${e.severity}: ${e.description}`
  ).join('\n');

  return `BATCH SECURITY ASSESSMENT — ${events.length} anomalies.

${agentContext}

Events:
${summary}

Are any of these inconsistent with the agent's purpose? Flag only genuinely suspicious items.
Format: EVENT_NUM: ALLOW/ALERT/PAUSE/KILL — one sentence reason`;
}

function parseAssessment(content: string, tokens: number, cost: number): LLMAssessment {
  const lines = content.trim().split('\n');
  let consistent = true;
  let confidence = 0.5;
  let reasoning = 'No assessment available';
  let recommendation: LLMAssessment['recommendation'] = 'allow';

  for (const line of lines) {
    const upper = line.toUpperCase();
    if (upper.startsWith('CONSISTENT:')) {
      consistent = upper.includes('YES');
    } else if (upper.startsWith('CONFIDENCE:')) {
      const val = parseFloat(line.split(':')[1]?.trim() ?? '0.5');
      confidence = isNaN(val) ? 0.5 : Math.max(0, Math.min(1, val));
    } else if (upper.startsWith('REASONING:')) {
      reasoning = line.split(':').slice(1).join(':').trim();
    } else if (upper.startsWith('ACTION:')) {
      const action = line.split(':')[1]?.trim().toUpperCase();
      if (action === 'ALERT') recommendation = 'alert';
      else if (action === 'PAUSE') recommendation = 'pause';
      else if (action === 'KILL') recommendation = 'kill';
      else recommendation = 'allow';
    }
  }

  return { consistent, confidence, reasoning, recommendation, tokensUsed: tokens, estimatedCost: cost };
}

function severityIndex(severity: EventSeverity): number {
  return SEVERITY_ORDER.indexOf(severity);
}
