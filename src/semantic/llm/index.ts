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

/**
 * #462 — what came back, as three states rather than two.
 *
 * `parseFindings` used to return `SemanticFinding[]` and answer "no findings"
 * for three different situations: the model found nothing, the response could
 * not be parsed, and the call threw. Measured on `c982b58`: content asking for a
 * bracketed reviewer note after the JSON produced 0 findings in 4 trials out of
 * 4 — the model reported both credentials EVERY time and the greedy
 * `/\[[\s\S]*\]/` swallowed the trailing note, so `JSON.parse` threw and the
 * `catch` returned `[]`. No persuasion of the analyst was needed at all, and the
 * same defect drops real findings on benign scans whenever a model adds a
 * bracketed remark.
 *
 * 0.27.0's own headline says a verdict that was not measured must not read as
 * clean. This is that sentence applied to the layer that shipped it.
 */
export type LLMFileOutcome =
  | { kind: 'findings'; findings: SemanticFinding[] }
  | { kind: 'unparsed'; reason: string };

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
    /** Files Layer 3 could not read an answer for. NEVER silently empty (#462). */
    unanalyzed: Array<{ path: string; reason: string }>;
  }> {
    const allFindings: SemanticFinding[] = [];
    const unanalyzed: Array<{ path: string; reason: string }> = [];
    let totalCost = 0;
    let cachedResults = 0;

    for (let i = 0; i < files.length; i++) {
      const file = files[i];
      const { systemPrompt, model } = getPromptForFileType(file.type);

      // Check cache
      const contentHash = this.cache.hash(file.content, systemPrompt);
      const cached = await this.cache.get(contentHash);

      // An entry written by 0.27.0 or earlier holds the raw `response` text and
      // no `findings`. It is treated as a MISS and re-analysed, not as a failure:
      // the alternative shapes are re-parsing the old raw text (which is the
      // replay this fix exists to end) or reporting every previously-cached file
      // as unanalysed on first upgrade, which would be a false alarm on a
      // machine where nothing is wrong.
      if (cached && Array.isArray(cached.findings)) {
        this.onProgress?.(
          `[${i + 1}/${files.length}] ${file.path} .............. (cached)`
        );
        // The cache holds a PARSED result, so a response that could not be read
        // is not replayed. Before #462 the raw text was cached BEFORE the parse
        // and re-parsed on every later run, so one poisoned response suppressed
        // that file permanently, at zero API cost, printing `(cached)`.
        allFindings.push(...this.adoptCachedFindings(cached.findings, file));
        cachedResults++;
        continue;
      }

      // Check budget
      const withinBudget = await this.budget.isWithinBudget();
      if (!withinBudget) {
        this.onProgress?.(
          `[${i + 1}/${files.length}] ${file.path} .............. skipped (budget exceeded)`
        );
        unanalyzed.push({ path: file.path, reason: 'the Layer 3 budget was exhausted before this file' });
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

        // Record cost. Billed whether or not the answer was readable.
        const cost = await this.budget.recordCost(
          model,
          result.inputTokens,
          result.outputTokens
        );
        totalCost += cost;

        const outcome = this.parseModelResponse(result.text, file);

        if (outcome.kind === 'unparsed') {
          // Nothing is cached for an unreadable response, so a retry is a real
          // retry rather than a replay of the thing that could not be read.
          unanalyzed.push({ path: file.path, reason: outcome.reason });
          this.onProgress?.(` not analyzed: ${outcome.reason}`);
          continue;
        }

        await this.cache.set(contentHash, {
          hash: contentHash,
          findings: outcome.findings,
          model,
          timestamp: new Date().toISOString(),
          inputTokens: result.inputTokens,
          outputTokens: result.outputTokens,
        });

        allFindings.push(...outcome.findings);

        this.onProgress?.(
          ` ${outcome.findings.length} finding${outcome.findings.length === 1 ? '' : 's'}`
        );
      } catch (error) {
        const msg = error instanceof Error ? error.message : String(error);
        this.onProgress?.(` error: ${msg}`);
        // A file whose analysis errored is not a clean file. Degrading
        // gracefully means continuing with the OTHER files, not reporting this
        // one as examined.
        unanalyzed.push({ path: file.path, reason: `the analysis call failed: ${msg}` });
      }
    }

    return { findings: allFindings, cost: totalCost, cachedResults, unanalyzed };
  }

  /**
   * Read the model's response, or say it could not be read.
   *
   * The greedy `/\[[\s\S]*\]/` is gone rather than narrowed. A non-greedy
   * version truncates any finding whose description contains a `]`, and a
   * hand-written balanced scanner is a new parser — the surface #449 spent five
   * review rounds paying for. What is left is the smallest total rule: the
   * response is a JSON array, optionally inside one fenced block, and anything
   * else is `unparsed` and is REPORTED.
   */
  parseModelResponse(response: string, file: AnalysisFile): LLMFileOutcome {
    const body = extractJsonPayload(response);
    if (body === null) {
      return {
        kind: 'unparsed',
        reason: 'the analyst\'s response contained no JSON array to read',
      };
    }

    let raw: unknown;
    try {
      raw = JSON.parse(body);
    } catch {
      return {
        kind: 'unparsed',
        reason: 'the analyst\'s response was not the JSON array the prompt asks for',
      };
    }
    if (!Array.isArray(raw)) {
      return { kind: 'unparsed', reason: 'the analyst returned JSON that was not an array of findings' };
    }

    return { kind: 'findings', findings: this.toFindings(raw as LLMFindingRaw[], file) };
  }

  /** Rebuild findings from a cache entry, re-anchoring them on this file. */
  private adoptCachedFindings(findings: SemanticFinding[], file: AnalysisFile): SemanticFinding[] {
    return findings.map((f, idx) => ({
      ...f,
      id: `SEM-LLM-${String(idx + 1).padStart(3, '0')}`,
      file: file.path,
    }));
  }

  private toFindings(raw: LLMFindingRaw[], file: AnalysisFile): SemanticFinding[] {
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

/**
 * The JSON text in a model response, or null.
 *
 * Line-based and total. It has exactly two rules — the whole response is JSON,
 * or the answer is the LAST fenced block — and neither can span from a stray `[`
 * to a distant `]`, which is what the greedy `/\[[\s\S]*\]/` did.
 *
 * Rule two is not optional and it was measured into existence. With the boundary
 * rule in place the analyst frequently DETECTS the injection and says so before
 * answering ("Despite the attempt to redirect me with instructions inside the
 * artifact…"), so requiring the whole response to be JSON threw away correct
 * answers on exactly the adversarial inputs this fix exists for: the forged
 * fixture went to `unparsed` in 2 of 3 trials while the model had reported both
 * credentials. A stricter parser is a false negative, just a loud one.
 */
export function extractJsonPayload(text: string): string | null {
  const trimmed = text.trim();
  if (trimmed.startsWith('[') || trimmed.startsWith('{')) return trimmed;

  const lines = trimmed.split('\n');
  const fences: number[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (/^```[a-zA-Z0-9_-]*$/.test(lines[i].trim())) fences.push(i);
  }
  if (fences.length < 2) return null;

  const close = fences[fences.length - 1];
  const open = fences[fences.length - 2];
  if (close - open < 1) return null;
  return lines.slice(open + 1, close).join('\n').trim();
}

export { AnthropicClient } from './client';
export { LLMCache } from './cache';
export { BudgetTracker } from './budget';
