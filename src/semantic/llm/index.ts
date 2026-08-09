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
   * review rounds paying for.
   *
   * The first replacement was two rules — "starts with a bracket" or "the last
   * fenced block" — and it was measured against the OLD parser on twenty
   * response shapes: it lost a CRITICAL credential finding on six of them,
   * including an unfenced array after prose and a `{"findings":[…]}` wrapper.
   * End to end that took `secure --deep` on a file holding a plaintext operator
   * credential from `69/100 exit 1` to `93/100 exit 0` — the same file, the same
   * analyst verdict, and only the model's FORMATTING different. Trading a
   * suppression defect for a formatting-dependent CI gate is not a fix.
   *
   * So there are no per-shape rules. There is a short, general list of CANDIDATE
   * slices, and `JSON.parse` is still the only parser — each candidate is handed
   * to it and the first that yields an array of findings wins. Adding a shape
   * does not add a branch; a response nothing recognises is `unparsed` and is
   * REPORTED, never silently clean.
   */
  parseModelResponse(response: string, file: AnalysisFile): LLMFileOutcome {
    const raw = extractFindingsArray(response);
    if (raw === null) {
      return {
        kind: 'unparsed',
        reason: 'the analyst\'s response did not contain the JSON array of findings the prompt asks for',
      };
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

/** A fence line, whichever of the two markdown spellings the model chose. */
const FENCE_LINE = /^(?:```|~~~)[a-zA-Z0-9_-]*$/;

/**
 * The contents of each fenced block, in order.
 *
 * An unclosed final fence runs to the end of the response rather than being
 * discarded: a truncated answer is still an answer, and dropping it reported a
 * file as unread when the findings were sitting right there.
 */
function fencedBlocks(lines: string[]): string[] {
  const fences: number[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (FENCE_LINE.test(lines[i].trim())) fences.push(i);
  }
  const blocks: string[] = [];
  for (let i = 0; i < fences.length; i += 2) {
    const open = fences[i];
    const close = i + 1 < fences.length ? fences[i + 1] : lines.length;
    if (close - open > 1) blocks.push(lines.slice(open + 1, close).join('\n').trim());
  }
  return blocks;
}

/**
 * Slices of the response that might BE the answer, most-likely first.
 *
 * Deliberately a short general list rather than a rule per response shape: the
 * previous two-rule version lost a finding on six of twenty measured shapes, and
 * answering that with six more rules is how a parser becomes the defect. Nothing
 * here decides whether a slice is valid — `JSON.parse` does.
 */
function* jsonCandidates(text: string): Generator<string> {
  const trimmed = text.trim();
  if (!trimmed) return;
  yield trimmed;

  // Later blocks first: when the analyst quotes the artifact before answering,
  // the quote comes first and the answer last.
  const blocks = fencedBlocks(trimmed.split('\n'));
  for (let i = blocks.length - 1; i >= 0; i--) yield blocks[i];

  // A bare array or object sitting in prose. These CAN span from a stray `[` to
  // a distant `]` — that is exactly the greedy match — but they are last, they
  // are only reached when everything better failed, and `JSON.parse` has to
  // accept the result. The greedy regex's defect was never the span; it was that
  // the span's failure was swallowed and reported as a clean file.
  const spans: Array<[number, number]> = [
    [trimmed.indexOf('['), trimmed.lastIndexOf(']')],
    [trimmed.indexOf('{'), trimmed.lastIndexOf('}')],
  ];
  for (const [start, end] of spans) {
    if (start !== -1 && end > start) yield trimmed.slice(start, end + 1);
  }
}

/** The findings array inside one candidate slice, or null if it is not one. */
function findingsArrayFrom(candidate: string): unknown[] | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(candidate);
  } catch {
    return null;
  }
  if (Array.isArray(parsed)) return parsed;
  // `{"findings":[…]}` is a shape models return unprompted, and the old parser
  // read it correctly by accident — its greedy match found the inner array. It
  // is accepted explicitly rather than lost to the tightening.
  if (parsed && typeof parsed === 'object') {
    const wrapped = (parsed as Record<string, unknown>).findings;
    if (Array.isArray(wrapped)) return wrapped;
  }
  return null;
}

/** The model's findings array, or null when no slice of the response is one. */
export function extractFindingsArray(text: string): unknown[] | null {
  for (const candidate of jsonCandidates(text)) {
    const arr = findingsArrayFrom(candidate);
    if (arr !== null) return arr;
  }
  return null;
}

/**
 * The JSON text of the winning candidate, for tests and callers that want the
 * slice rather than the parsed value.
 */
export function extractJsonPayload(text: string): string | null {
  for (const candidate of jsonCandidates(text)) {
    if (findingsArrayFrom(candidate) !== null) return candidate;
  }
  return null;
}

export { AnthropicClient } from './client';
export { LLMCache } from './cache';
export { BudgetTracker } from './budget';
