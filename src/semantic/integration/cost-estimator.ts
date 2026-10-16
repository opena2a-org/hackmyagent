/**
 * Cost Estimator
 *
 * Pre-scan cost estimation for Layer 3 LLM analysis.
 * Estimates token counts and costs before making API calls.
 */

import type { AnalysisFile, CostEstimate } from '../types';
import { LLMCache } from '../llm/cache';
import { BudgetTracker } from '../llm/budget';
import { getPromptForFileType, REPORT_FINDINGS_TOOL } from '../llm/prompts';
import { partitionForEgress, redactForEgress } from '../egress';

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
   *
   * Counts only the files Layer 3 sends: env and config files are withheld by
   * design and cost nothing.
   */
  async estimate(files: AnalysisFile[]): Promise<CostEstimate> {
    let totalInputTokens = 0;
    let totalOutputTokens = 0;
    let totalCost = 0;
    let cachedFiles = 0;

    const { send } = partitionForEgress(files);
    for (const file of send) {
      const prompt = getPromptForFileType(file.type);
      if (prompt === null) continue;
      const { systemPrompt, model } = prompt;
      // The key `LLMAnalyzer` writes: the redacted text, the prompt and the tool schema.
      const contentHash = this.cache.hash(
        redactForEgress(file.content).text,
        systemPrompt + JSON.stringify(REPORT_FINDINGS_TOOL),
      );

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
      fileCount: send.length,
      estimatedInputTokens: totalInputTokens,
      estimatedOutputTokens: totalOutputTokens,
      estimatedCostUsd: Math.round(totalCost * 1000) / 1000,
      cachedFiles,
    };
  }
}
