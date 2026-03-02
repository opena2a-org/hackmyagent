import type { LLMAdapter, LLMResponse } from '../../arp';

interface MockCall {
  prompt: string;
  maxTokens: number;
  timestamp: number;
}

/**
 * Deterministic LLM adapter for testing L2 intelligence layer.
 * Returns structured responses based on input patterns.
 */
export class MockLLMAdapter implements LLMAdapter {
  readonly name = 'mock';
  private calls: MockCall[] = [];
  private latencyMs: number;
  private costPerCall: number;

  constructor(options?: { latencyMs?: number; costPerCall?: number }) {
    this.latencyMs = options?.latencyMs ?? 10;
    this.costPerCall = options?.costPerCall ?? 0.001;
  }

  async assess(prompt: string, maxTokens: number): Promise<LLMResponse> {
    this.calls.push({ prompt, maxTokens, timestamp: Date.now() });

    if (this.latencyMs > 0) {
      await new Promise((r) => setTimeout(r, this.latencyMs));
    }

    const response = this.generateResponse(prompt);

    return {
      content: response,
      inputTokens: Math.ceil(prompt.length / 4),
      outputTokens: Math.ceil(response.length / 4),
      model: 'mock-llm',
    };
  }

  estimateCost(inputTokens: number, outputTokens: number): number {
    return this.costPerCall;
  }

  async healthCheck(): Promise<boolean> {
    return true;
  }

  /** Get number of calls made */
  getCallCount(): number {
    return this.calls.length;
  }

  /** Get all calls for assertions */
  getCalls(): MockCall[] {
    return [...this.calls];
  }

  /** Get the most recent call */
  getLastCall(): MockCall | undefined {
    return this.calls[this.calls.length - 1];
  }

  /** Reset call history */
  reset(): void {
    this.calls = [];
  }

  private generateResponse(prompt: string): string {
    const lower = prompt.toLowerCase();

    // Threat patterns - always flag
    if (lower.includes('threat') || lower.includes('critical') || lower.includes('kill')) {
      return 'CONSISTENT: NO\nCONFIDENCE: 0.95\nREASONING: Activity matches known attack pattern\nACTION: KILL';
    }

    // Violation patterns - flag as suspicious
    if (lower.includes('violation') || lower.includes('suspicious') || lower.includes('high')) {
      return 'CONSISTENT: NO\nCONFIDENCE: 0.80\nREASONING: Behavior deviates from declared capabilities\nACTION: ALERT';
    }

    // Anomaly patterns - moderate concern
    if (lower.includes('anomaly') || lower.includes('unusual')) {
      return 'CONSISTENT: NO\nCONFIDENCE: 0.60\nREASONING: Statistical anomaly detected but uncertain\nACTION: ALERT';
    }

    // Default - allow
    return 'CONSISTENT: YES\nCONFIDENCE: 0.90\nREASONING: Activity consistent with agent purpose\nACTION: ALLOW';
  }
}
