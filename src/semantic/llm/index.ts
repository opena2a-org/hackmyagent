/**
 * LLM Analyzer (Layer 3 Orchestrator)
 *
 * Coordinates LLM-powered analysis for standalone CLI mode (--deep).
 * Uses the Anthropic API directly with caching and budget control.
 *
 * NOT used in MCP server mode — there, the host LLM does the reasoning.
 */

import type { SemanticFinding, AnalysisFile, LLMAnalysisOptions } from '../types';
import { AnthropicClient } from './client';
import { LLMCache } from './cache';
import { BudgetTracker } from './budget';
import { getPromptForFileType, buildFileAnalysisMessage } from './prompts';

interface LLMFindingRaw {
  line?: number;
  type?: string;
  severity?: string;
  description?: string;
  rationale?: string;
  recommendation?: string;
}

export class LLMAnalyzer {
  private client: AnthropicClient;
  private cache: LLMCache;
  private budget: BudgetTracker;
  private onProgress?: (message: string) => void;

  constructor(options: LLMAnalysisOptions) {
    this.client = new AnthropicClient(options.apiKey);
    this.cache = new LLMCache(options.cacheDir);
    this.budget = new BudgetTracker(options.budgetCap, options.cacheDir);
    this.onProgress = options.onProgress;
  }

  /**
   * Analyze files using LLM. Respects cache and budget.
   */
  async analyze(files: AnalysisFile[]): Promise<{
    findings: SemanticFinding[];
    cost: number;
    cachedResults: number;
  }> {
    const allFindings: SemanticFinding[] = [];
    let totalCost = 0;
    let cachedResults = 0;

    for (let i = 0; i < files.length; i++) {
      const file = files[i];
      const { systemPrompt, model } = getPromptForFileType(file.type);

      // Check cache
      const contentHash = this.cache.hash(file.content, systemPrompt);
      const cached = await this.cache.get(contentHash);

      if (cached) {
        this.onProgress?.(
          `[${i + 1}/${files.length}] ${file.path} .............. (cached)`
        );
        const findings = this.parseFindings(cached.response, file);
        allFindings.push(...findings);
        cachedResults++;
        continue;
      }

      // Check budget
      const withinBudget = await this.budget.isWithinBudget();
      if (!withinBudget) {
        this.onProgress?.(
          `[${i + 1}/${files.length}] ${file.path} .............. skipped (budget exceeded)`
        );
        continue;
      }

      // Call LLM
      this.onProgress?.(
        `[${i + 1}/${files.length}] ${file.path} ..............`
      );

      try {
        const userMessage = buildFileAnalysisMessage(
          file.path,
          file.content,
          file.type
        );

        const result = await this.client.chat(
          model,
          systemPrompt,
          userMessage
        );

        // Cache the response
        await this.cache.set(contentHash, {
          hash: contentHash,
          response: result.text,
          model,
          timestamp: new Date().toISOString(),
          inputTokens: result.inputTokens,
          outputTokens: result.outputTokens,
        });

        // Record cost
        const cost = await this.budget.recordCost(
          model,
          result.inputTokens,
          result.outputTokens
        );
        totalCost += cost;

        // Parse findings
        const findings = this.parseFindings(result.text, file);
        allFindings.push(...findings);

        this.onProgress?.(
          ` ${findings.length} finding${findings.length === 1 ? '' : 's'}`
        );
      } catch (error) {
        const msg = error instanceof Error ? error.message : String(error);
        this.onProgress?.(` error: ${msg}`);
        // Graceful degradation — continue with remaining files
      }
    }

    return { findings: allFindings, cost: totalCost, cachedResults };
  }

  /**
   * Parse JSON findings from LLM response.
   */
  private parseFindings(
    response: string,
    file: AnalysisFile
  ): SemanticFinding[] {
    try {
      // Extract JSON array from response (may have markdown code blocks)
      const jsonMatch = response.match(/\[[\s\S]*\]/);
      if (!jsonMatch) return [];

      const raw = JSON.parse(jsonMatch[0]) as LLMFindingRaw[];
      if (!Array.isArray(raw)) return [];

      return raw
        .filter((f) => f.description && f.severity)
        .map((f, idx) => ({
          id: `SEM-LLM-${String(idx + 1).padStart(3, '0')}`,
          title: f.type || 'LLM finding',
          description: f.description || '',
          rationale: f.rationale || '',
          category: 'credential' as const,
          severity: this.normalizeSeverity(f.severity || 'medium'),
          file: file.path,
          line: f.line ?? undefined,
          recommendation: f.recommendation || 'Review and remediate.',
          layer: 3 as const,
          autoFixable: false,
        }));
    } catch {
      return [];
    }
  }

  private normalizeSeverity(
    s: string
  ): 'critical' | 'high' | 'medium' | 'low' {
    const lower = s.toLowerCase();
    if (lower === 'critical') return 'critical';
    if (lower === 'high') return 'high';
    if (lower === 'medium') return 'medium';
    return 'low';
  }
}

export { AnthropicClient } from './client';
export { LLMCache } from './cache';
export { BudgetTracker } from './budget';
