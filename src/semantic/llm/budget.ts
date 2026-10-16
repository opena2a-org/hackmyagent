/**
 * LLM Budget Tracking (Layer 3)
 *
 * Tracks daily LLM API spend and enforces budget cap.
 * Default: $1/day (configurable via HACKMYAGENT_LLM_BUDGET env var).
 * The record sits beside the Layer 3 cache, in the state directory of the
 * scanned tree (`layer3CacheDir`).
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import { ensurePrivateDir, layer3CacheDir } from './cache';

/** Anthropic API pricing (per 1M tokens) */
const PRICING = {
  haiku: { input: 0.25, output: 1.25 },
  sonnet: { input: 3.0, output: 15.0 },
};

export interface BudgetState {
  date: string; // YYYY-MM-DD
  totalCostUsd: number;
  requests: number;
}

export class BudgetTracker {
  private budgetCap: number;
  private cacheDir: string | null;
  /** Today's record when there is no directory to keep it in. */
  private memory: BudgetState | null = null;

  /**
   * `cacheDir` is the directory to keep the record in. Left out, it is the
   * state directory of the working directory's tree; `null` keeps the record
   * for the life of this tracker only.
   */
  constructor(budgetCapUsd?: number, cacheDir?: string | null) {
    this.budgetCap = budgetCapUsd ??
      parseFloat(process.env.HACKMYAGENT_LLM_BUDGET || '1.0');
    this.cacheDir = cacheDir === undefined ? layer3CacheDir(process.cwd()) : cacheDir;
  }

  /**
   * Calculate cost for a request.
   */
  calculateCost(
    model: 'haiku' | 'sonnet',
    inputTokens: number,
    outputTokens: number
  ): number {
    const pricing = PRICING[model];
    return (
      (inputTokens / 1_000_000) * pricing.input +
      (outputTokens / 1_000_000) * pricing.output
    );
  }

  /**
   * Estimate cost before making a request.
   */
  estimateCost(
    model: 'haiku' | 'sonnet',
    estimatedInputTokens: number,
    estimatedOutputTokens: number = 1000
  ): number {
    return this.calculateCost(model, estimatedInputTokens, estimatedOutputTokens);
  }

  /**
   * Check if we're within budget for today.
   */
  async isWithinBudget(): Promise<boolean> {
    const state = await this.loadState();
    return state.totalCostUsd < this.budgetCap;
  }

  /**
   * Get remaining budget for today.
   */
  async remainingBudget(): Promise<number> {
    const state = await this.loadState();
    return Math.max(0, this.budgetCap - state.totalCostUsd);
  }

  /**
   * Record a completed request's cost.
   */
  async recordCost(
    model: 'haiku' | 'sonnet',
    inputTokens: number,
    outputTokens: number
  ): Promise<number> {
    const cost = this.calculateCost(model, inputTokens, outputTokens);
    const state = await this.loadState();
    state.totalCostUsd += cost;
    state.requests += 1;
    await this.saveState(state);
    return cost;
  }

  /**
   * Get today's spend summary.
   */
  async getSummary(): Promise<{ spent: number; cap: number; remaining: number; requests: number }> {
    const state = await this.loadState();
    return {
      spent: state.totalCostUsd,
      cap: this.budgetCap,
      remaining: Math.max(0, this.budgetCap - state.totalCostUsd),
      requests: state.requests,
    };
  }

  private todayKey(): string {
    return new Date().toISOString().split('T')[0];
  }

  private async loadState(): Promise<BudgetState> {
    const today = this.todayKey();
    if (this.cacheDir === null) {
      return this.memory?.date === today
        ? { ...this.memory }
        : { date: today, totalCostUsd: 0, requests: 0 };
    }
    try {
      const data = await fs.readFile(path.join(this.cacheDir, 'budget.json'), 'utf-8');
      const state = JSON.parse(data) as BudgetState;
      // Reset if it's a new day
      if (state.date !== today) {
        return { date: today, totalCostUsd: 0, requests: 0 };
      }
      return state;
    } catch {
      return { date: today, totalCostUsd: 0, requests: 0 };
    }
  }

  private async saveState(state: BudgetState): Promise<void> {
    if (this.cacheDir === null) {
      this.memory = { ...state };
      return;
    }
    try {
      await ensurePrivateDir(this.cacheDir);
      await fs.writeFile(path.join(this.cacheDir, 'budget.json'), JSON.stringify(state, null, 2), { mode: 0o600 });
    } catch {
      // Budget write failures are non-fatal
    }
  }
}
