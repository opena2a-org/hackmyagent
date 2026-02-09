/**
 * Cost Estimator
 *
 * Pre-scan cost estimation for Layer 3 LLM analysis.
 * Estimates token counts and costs before making API calls.
 */

import type { AnalysisFile, CostEstimate } from '../types';
import { LLMCache } from '../llm/cache';
import { BudgetTracker } from '../llm/budget';
import { getPromptForFileType } from '../llm/prompts';

/** Rough estimate: 1 token ≈ 4 characters */
const CHARS_PER_TOKEN = 4;

/** Estimated output tokens per file */
const ESTIMATED_OUTPUT_TOKENS = 1000;

export class CostEstimator {
  private cache: LLMCache;
  private budget: BudgetTracker;

  constructor(cacheDir?: string) {
    this.cache = new LLMCache(cacheDir);
    this.budget = new BudgetTracker(undefined, cacheDir);
  }

  /**
   * Estimate cost for analyzing a set of files.
   */
  async estimate(files: AnalysisFile[]): Promise<CostEstimate> {
    let totalInputTokens = 0;
    let totalOutputTokens = 0;
    let totalCost = 0;
    let cachedFiles = 0;

    for (const file of files) {
      const { systemPrompt, model } = getPromptForFileType(file.type);
      const contentHash = this.cache.hash(file.content, systemPrompt);

      if (await this.cache.has(contentHash)) {
        cachedFiles++;
        continue;
      }

      // Estimate tokens
      const inputTokens = Math.ceil(
        (file.content.length + systemPrompt.length) / CHARS_PER_TOKEN
      );
      totalInputTokens += inputTokens;
      totalOutputTokens += ESTIMATED_OUTPUT_TOKENS;

      // Estimate cost
      totalCost += this.budget.estimateCost(
        model,
        inputTokens,
        ESTIMATED_OUTPUT_TOKENS
      );
    }

    return {
      fileCount: files.length,
      estimatedInputTokens: totalInputTokens,
      estimatedOutputTokens: totalOutputTokens,
      estimatedCostUsd: Math.round(totalCost * 1000) / 1000,
      cachedFiles,
    };
  }
}
