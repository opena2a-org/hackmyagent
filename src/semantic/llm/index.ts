/**
 * LLM Analyzer (Layer 3 Orchestrator)
 *
 * Coordinates LLM-powered analysis for standalone CLI mode (--deep).
 * Uses the Anthropic API directly with caching and budget control.
 *
 * NOT used in MCP server mode — there, the host LLM does the reasoning.
 */

import type { SemanticFinding, AnalysisFile, LLMAnalysisOptions } from '../types';
import { AnthropicClient, type AnthropicToolResponse } from './client';
import { LLMCache, layer3CacheDir } from './cache';
import { BudgetTracker } from './budget';
import { getPromptForFileType, buildFileAnalysisMessage, REPORT_FINDINGS_TOOL } from './prompts';
import {
  partitionForEgress,
  redactForEgress,
  OVER_REDACTION_LIMIT_REASON,
  type WithheldFile,
} from '../egress';

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
 *
 * The states are decided by the transport, not by reading reply text: see
 * `readToolResponse`. A reply that carries no findings report is `unparsed`.
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
  private onSend?: (plan: { files: number; requests: number }) => void;

  constructor(options: LLMAnalysisOptions) {
    this.client = new AnthropicClient(options.apiKey);
    const cacheDir = options.cacheDir !== undefined
      ? options.cacheDir
      : layer3CacheDir(options.scanRoot ?? process.cwd());
    this.cache = new LLMCache(cacheDir);
    this.budget = new BudgetTracker(options.budgetCap, cacheDir);
    this.onProgress = options.onProgress;
    this.onSend = options.onSend;
  }

  /**
   * Analyze files using LLM. Respects cache and budget.
   *
   * Env and config files are withheld here, whatever the caller passes, and
   * every file that is sent is redacted before its cache key is computed and
   * before the request is built (`../egress.ts`). `onSend` is called once,
   * before the first request, with the number of files that will be sent;
   * each is one request, and a file answered from the cache is not counted.
   */
  async analyze(files: AnalysisFile[]): Promise<{
    findings: SemanticFinding[];
    cost: number;
    cachedResults: number;
    /** Files Layer 3 could not read an answer for. NEVER silently empty (#462). */
    unanalyzed: Array<{ path: string; reason: string }>;
    /** Env and config files, not sent by design. Not analysed and not a failed analysis. */
    withheld: WithheldFile[];
  }> {
    const allFindings: SemanticFinding[] = [];
    const unanalyzed: Array<{ path: string; reason: string }> = [];
    let totalCost = 0;
    let cachedResults = 0;

    const { send, withheld } = partitionForEgress(files);

    // Plan every file before the first request, so the notice can state the
    // number of requests the run will make.
    const plan: Array<{
      file: AnalysisFile;
      text: string;
      systemPrompt: string;
      model: 'haiku' | 'sonnet';
      contentHash: string;
      cached: Awaited<ReturnType<LLMCache['get']>>;
    }> = [];
    for (const file of send) {
      const prompt = getPromptForFileType(file.type);
      if (prompt === null) {
        withheld.push({ path: file.path, type: file.type, reason: 'Layer 3 has no analysis for this kind of file' });
        continue;
      }
      const { text, overLimit } = redactForEgress(file.content);
      if (overLimit) {
        unanalyzed.push({ path: file.path, reason: OVER_REDACTION_LIMIT_REASON });
        continue;
      }
      // The cache key is the REDACTED text with the prompt and the tool schema:
      // the three together are what the cached answer was given in reply to.
      const contentHash = this.cache.hash(
        text,
        prompt.systemPrompt + JSON.stringify(REPORT_FINDINGS_TOOL)
      );
      const cached = await this.cache.get(contentHash);
      plan.push({ file, text, systemPrompt: prompt.systemPrompt, model: prompt.model, contentHash, cached });
    }

    const toSend = plan.filter((p) => !isUsableCacheEntry(p.cached)).length;
    if (toSend > 0) this.onSend?.({ files: toSend, requests: toSend });

    for (let i = 0; i < plan.length; i++) {
      const { file, text, systemPrompt, model, contentHash, cached } = plan[i];

      // An entry written by 0.27.0 or earlier holds the raw `response` text and
      // no `findings`. It is treated as a MISS and re-analysed, not as a failure:
      // the alternative shapes are re-parsing the old raw text (which is the
      // replay this fix exists to end) or reporting every previously-cached file
      // as unanalysed on first upgrade, which would be a false alarm on a
      // machine where nothing is wrong.
      if (cached && isUsableCacheEntry(cached)) {
        this.onProgress?.(
          `[${i + 1}/${plan.length}] ${file.path} .............. (cached)`
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
          `[${i + 1}/${plan.length}] ${file.path} .............. skipped (budget exceeded)`
        );
        unanalyzed.push({ path: file.path, reason: 'the Layer 3 budget was exhausted before this file' });
        continue;
      }

      // Call LLM
      this.onProgress?.(
        `[${i + 1}/${plan.length}] ${file.path} ..............`
      );

      try {
        // `text`, never `file.content`: the request carries the redacted file.
        const userMessage = buildFileAnalysisMessage(
          file.path,
          text,
          file.type
        );

        const result = await this.client.callTool(
          model,
          systemPrompt,
          userMessage,
          REPORT_FINDINGS_TOOL
        );

        // Record cost. Billed whether or not the answer was readable.
        const cost = await this.budget.recordCost(
          model,
          result.inputTokens,
          result.outputTokens
        );
        totalCost += cost;

        const outcome = this.readToolResponse(result, file);

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

    return { findings: allFindings, cost: totalCost, cachedResults, unanalyzed, withheld };
  }

  /**
   * Read the analyst's answer from the transport, or say there is none.
   *
   * There is no extraction step. The answer is the input of the one
   * `report_findings` call, which the API returns already parsed, and the reply
   * text is never read, so no rule decides which text to believe.
   *
   * Structured output would MOVE the #462 failure rather than remove it if "no
   * tool call came back" were ever built as clean. So `findings` needs all of:
   * the reply stopped to make its call (`tool_use`), it made exactly one call,
   * to the tool it was offered, and that call holds a findings array whose
   * every entry has a severity and a description. Anything else is `unparsed`
   * and is REPORTED. An entry that cannot be read fails the whole answer
   * rather than being dropped: dropping it would turn a report of malformed
   * entries into zero findings, which is clean built from a non-answer.
   */
  readToolResponse(
    response: Pick<AnthropicToolResponse, 'stopReason' | 'toolCalls'>,
    file: AnalysisFile
  ): LLMFileOutcome {
    if (response.stopReason !== 'tool_use') {
      return { kind: 'unparsed', reason: describeStop(response.stopReason) };
    }

    const calls = response.toolCalls;
    if (calls.length === 0) {
      return { kind: 'unparsed', reason: 'the analyst returned no findings report' };
    }
    if (calls.length > 1) {
      return {
        kind: 'unparsed',
        reason: `the analyst returned ${calls.length} findings reports where exactly one was asked for`,
      };
    }
    if (calls[0].name !== REPORT_FINDINGS_TOOL.name) {
      return { kind: 'unparsed', reason: 'the analyst called a tool it was not offered' };
    }

    const input = calls[0].input;
    const entries = isRecord(input) ? input.findings : undefined;
    if (!Array.isArray(entries)) {
      return { kind: 'unparsed', reason: 'the analyst\'s findings report held no findings array' };
    }

    const unreadable = entries.filter((entry) => !isReadableFinding(entry)).length;
    if (unreadable > 0) {
      return {
        kind: 'unparsed',
        reason: `${unreadable} of the ${entries.length} entries in the analyst's findings report had no readable severity and description`,
      };
    }

    return { kind: 'findings', findings: this.toFindings(entries as LLMFindingRaw[], file) };
  }

  /** Rebuild findings from a cache entry, re-anchoring them on this file. */
  private adoptCachedFindings(findings: SemanticFinding[], file: AnalysisFile): SemanticFinding[] {
    return findings.map((f, idx) => ({
      ...f,
      id: `SEM-LLM-${String(idx + 1).padStart(3, '0')}`,
      file: file.path,
    }));
  }

  /** Every entry has already passed `isReadableFinding`, so none is dropped here. */
  private toFindings(raw: LLMFindingRaw[], file: AnalysisFile): SemanticFinding[] {
    return raw.map((f, idx) => ({
      id: `SEM-LLM-${String(idx + 1).padStart(3, '0')}`,
      title: f.type || 'LLM finding',
      description: f.description || '',
      rationale: f.rationale || '',
      category: 'credential' as const,
      severity: this.normalizeSeverity(f.severity || 'medium'),
      file: file.path,
      line: typeof f.line === 'number' ? f.line : undefined,
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
 * A cache entry that answers for its file. An entry written by 0.27.0 or
 * earlier holds no parsed `findings` and is a miss (see `analyze`).
 */
function isUsableCacheEntry(entry: { findings?: unknown } | null): boolean {
  return entry !== null && Array.isArray(entry.findings);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** An entry that names a severity and says what was found. */
function isReadableFinding(entry: unknown): boolean {
  return (
    isRecord(entry) &&
    typeof entry.severity === 'string' &&
    entry.severity.length > 0 &&
    typeof entry.description === 'string' &&
    entry.description.length > 0
  );
}

/** Why a reply that did not stop to make its call is not an answer. */
function describeStop(stopReason: string | null): string {
  if (stopReason === 'max_tokens') {
    return 'the analyst\'s answer was cut off at the output limit, so its findings report may be incomplete';
  }
  if (stopReason === 'refusal') return 'the analyst declined to analyze this file';
  if (stopReason === null) return 'the analyst\'s reply carried no stop reason';
  return `the analyst stopped (${JSON.stringify(stopReason)}) without returning its findings report`;
}

export { AnthropicClient } from './client';
export { LLMCache } from './cache';
export { BudgetTracker } from './budget';
