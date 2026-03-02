import { describe, it, expect, vi, beforeEach } from 'vitest';
import { LLMCache } from '../../src/semantic/llm/cache';
import { BudgetTracker } from '../../src/semantic/llm/budget';

describe('LLMCache', () => {
  it('generates consistent hashes for same content', () => {
    const cache = new LLMCache('/tmp/test-cache');
    const hash1 = cache.hash('file content', 'system prompt');
    const hash2 = cache.hash('file content', 'system prompt');
    expect(hash1).toBe(hash2);
  });

  it('generates different hashes for different content', () => {
    const cache = new LLMCache('/tmp/test-cache');
    const hash1 = cache.hash('content A', 'system prompt');
    const hash2 = cache.hash('content B', 'system prompt');
    expect(hash1).not.toBe(hash2);
  });

  it('generates different hashes for different prompts', () => {
    const cache = new LLMCache('/tmp/test-cache');
    const hash1 = cache.hash('content', 'prompt A');
    const hash2 = cache.hash('content', 'prompt B');
    expect(hash1).not.toBe(hash2);
  });
});

describe('BudgetTracker', () => {
  it('calculates cost correctly for Haiku', () => {
    const budget = new BudgetTracker(1.0, '/tmp/test-budget');
    // Haiku: $0.25/M input, $1.25/M output
    const cost = budget.calculateCost('haiku', 1_000_000, 1_000_000);
    expect(cost).toBeCloseTo(1.5, 2);
  });

  it('calculates cost correctly for Sonnet', () => {
    const budget = new BudgetTracker(1.0, '/tmp/test-budget');
    // Sonnet: $3.0/M input, $15.0/M output
    const cost = budget.calculateCost('sonnet', 1_000_000, 1_000_000);
    expect(cost).toBeCloseTo(18.0, 2);
  });

  it('estimates cost for small requests', () => {
    const budget = new BudgetTracker(1.0, '/tmp/test-budget');
    // 1000 input tokens, 500 output tokens with Haiku
    const cost = budget.estimateCost('haiku', 1000, 500);
    expect(cost).toBeLessThan(0.01);
  });
});
