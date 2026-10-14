/**
 * #462 — a response HackMyAgent could not read must never be reported as a
 * clean file.
 *
 * `parseFindings` extracted the model's JSON with a GREEDY `/\[[\s\S]*\]/` and
 * wrapped it in `catch { return []; }`. Measured on `c982b58`: a scanned file
 * asking for a bracketed reviewer note after the array produced 0 findings in
 * 4 trials of 4 — the analyst reported both credentials EVERY time, the greedy
 * match ran from the array's `[` to the `]` of the trailing note, `JSON.parse`
 * threw, and the catch returned an empty array.
 *
 * 0.28.0 narrowed the extractor to a line-based rule. This file pins its
 * removal: the analyst now answers through one forced `report_findings` tool
 * call, the API hands back the parsed input, and no text in the reply is ever
 * read as findings. The acceptance criterion is the pre-mortem: structured
 * output only MOVES the failure if "no tool call came back" is ever built as
 * clean, so every state below is decided by the transport — the stop reason and
 * the tool calls — and a missing call is `unparsed`.
 */
import { describe, it, expect, vi, afterEach } from 'vitest';
import { LLMAnalyzer } from '../../src/semantic/llm';
import { AnthropicClient, type AnthropicToolResponse } from '../../src/semantic/llm/client';
import {
  REPORT_FINDINGS_TOOL,
  CREDENTIAL_DETECTION_PROMPT,
  MCP_THREAT_ANALYSIS_PROMPT,
  INSTRUCTION_ANALYSIS_PROMPT,
} from '../../src/semantic/llm/prompts';
import type { AnalysisFile } from '../../src/semantic/types';

const FILE: AnalysisFile = { path: 'config.json', type: 'config_file', content: 'x', truncated: false };

const FINDING = {
  line: 3,
  type: 'Password',
  severity: 'critical',
  description: "Plain text password found: 'Wint3rmute-2026-office'",
  rationale: 'Administrative password stored in cleartext',
};

function analyzer(): LLMAnalyzer {
  return new LLMAnalyzer({ apiKey: 'unused-in-these-tests' } as never);
}

/** A transport result holding exactly one report call with this input. */
function reported(input: unknown, stopReason: string | null = 'tool_use'): AnthropicToolResponse {
  return {
    stopReason,
    toolCalls: [{ name: REPORT_FINDINGS_TOOL.name, input }],
    inputTokens: 1,
    outputTokens: 1,
  };
}

/** Stub `fetch` with one Messages API body and record the request it was sent. */
function stubMessagesApi(body: Record<string, unknown>): { requests: Array<Record<string, unknown>> } {
  const requests: Array<Record<string, unknown>> = [];
  vi.stubGlobal('fetch', vi.fn(async (_url: string, init: { body: string }) => {
    requests.push(JSON.parse(init.body));
    return {
      ok: true,
      status: 200,
      json: async () => ({ id: 'msg_stub', model: 'stub', usage: { input_tokens: 7, output_tokens: 3 }, ...body }),
      text: async () => '',
    };
  }));
  return { requests };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('#462 the request asks for a tool call, not for text', () => {
  it('forces exactly one report_findings call', async () => {
    const api = stubMessagesApi({ content: [], stop_reason: 'tool_use' });
    await new AnthropicClient('unused').callTool('haiku', 'system', 'user', REPORT_FINDINGS_TOOL);

    expect(api.requests).toHaveLength(1);
    const request = api.requests[0];
    expect(request.tools).toEqual([REPORT_FINDINGS_TOOL]);
    // `disable_parallel_tool_use` asks for one call rather than one or more. A
    // reply holding two anyway is refused below, never merged into one verdict.
    expect(request.tool_choice).toEqual({
      type: 'tool',
      name: REPORT_FINDINGS_TOOL.name,
      disable_parallel_tool_use: true,
    });
  });

  it('declares findings as a required array of objects', () => {
    const schema = REPORT_FINDINGS_TOOL.input_schema as any;
    expect(schema.type).toBe('object');
    expect(schema.required).toEqual(['findings']);
    expect(schema.properties.findings.type).toBe('array');
    expect(schema.properties.findings.items.required).toEqual(
      expect.arrayContaining(['severity', 'description']),
    );
  });

  it('hands back the stop reason and the tool calls, and no text', async () => {
    stubMessagesApi({
      content: [
        { type: 'text', text: JSON.stringify([FINDING]) },
        { type: 'tool_use', id: 'toolu_1', name: REPORT_FINDINGS_TOOL.name, input: { findings: [FINDING] } },
      ],
      stop_reason: 'tool_use',
    });
    const result = await new AnthropicClient('unused').callTool('haiku', 'system', 'user', REPORT_FINDINGS_TOOL);

    expect(result.stopReason).toBe('tool_use');
    expect(result.toolCalls).toEqual([{ name: REPORT_FINDINGS_TOOL.name, input: { findings: [FINDING] } }]);
    expect(result).not.toHaveProperty('text');
    expect(result.inputTokens).toBe(7);
    expect(result.outputTokens).toBe(3);
  });

  it('reports a missing stop reason as null rather than inventing one', async () => {
    stubMessagesApi({ content: [] });
    const result = await new AnthropicClient('unused').callTool('haiku', 'system', 'user', REPORT_FINDINGS_TOOL);
    expect(result.stopReason).toBeNull();
    expect(result.toolCalls).toEqual([]);
  });

  it('no longer tells the analyst to answer with a JSON array', () => {
    // The instruction scanned content was competing to override leaves the
    // prompt with the extractor: the format is the tool's schema now.
    for (const prompt of [CREDENTIAL_DETECTION_PROMPT, MCP_THREAT_ANALYSIS_PROMPT, INSTRUCTION_ANALYSIS_PROMPT]) {
      expect(prompt).not.toMatch(/JSON array/i);
      expect(prompt).not.toMatch(/respond with/i);
      expect(prompt).toContain(REPORT_FINDINGS_TOOL.name);
    }
  });
});

describe('#462 three states, built from the transport', () => {
  it('reports findings when one report call carries them', () => {
    const outcome = analyzer().readToolResponse(reported({ findings: [FINDING] }), FILE);
    expect(outcome.kind).toBe('findings');
    if (outcome.kind === 'findings') {
      expect(outcome.findings).toHaveLength(1);
      expect(outcome.findings[0].severity).toBe('critical');
      expect(outcome.findings[0].file).toBe('config.json');
      expect(outcome.findings[0].line).toBe(3);
    }
  });

  it('reports CLEAN as findings-with-none, distinct from unreadable', () => {
    const outcome = analyzer().readToolResponse(reported({ findings: [] }), FILE);
    expect(outcome.kind).toBe('findings');
    if (outcome.kind === 'findings') expect(outcome.findings).toHaveLength(0);
  });

  it('reports UNPARSED when no tool call came back, even beside a readable array in text', () => {
    // The pre-mortem in one case. The old extractor would have read this text
    // as one finding; the transport carried no report, so nothing was reported.
    const outcome = analyzer().readToolResponse(
      { stopReason: 'end_turn', toolCalls: [], inputTokens: 1, outputTokens: 1 },
      FILE,
    );
    expect(outcome.kind).toBe('unparsed');
    if (outcome.kind === 'unparsed') expect(outcome.reason).toMatch(/end_turn/);
  });

  it('reports UNPARSED when the stop reason is tool_use and the call list is empty', () => {
    const outcome = analyzer().readToolResponse(
      { stopReason: 'tool_use', toolCalls: [], inputTokens: 1, outputTokens: 1 },
      FILE,
    );
    expect(outcome.kind).toBe('unparsed');
    if (outcome.kind === 'unparsed') expect(outcome.reason).toMatch(/no findings report/);
  });

  it('reports UNPARSED when the answer was cut off at the output limit', () => {
    // A truncated report can still arrive as a well-formed but SHORTER array.
    // Read as complete, it would drop the findings after the cut silently.
    const outcome = analyzer().readToolResponse(reported({ findings: [FINDING] }, 'max_tokens'), FILE);
    expect(outcome.kind).toBe('unparsed');
    if (outcome.kind === 'unparsed') expect(outcome.reason).toMatch(/output limit/);
  });

  it('reports UNPARSED when the analyst declined', () => {
    const outcome = analyzer().readToolResponse(
      { stopReason: 'refusal', toolCalls: [], inputTokens: 1, outputTokens: 1 },
      FILE,
    );
    expect(outcome.kind).toBe('unparsed');
    if (outcome.kind === 'unparsed') expect(outcome.reason).toMatch(/declined/);
  });

  it('reports UNPARSED when the stop reason is missing', () => {
    const outcome = analyzer().readToolResponse(reported({ findings: [] }, null), FILE);
    expect(outcome.kind).toBe('unparsed');
  });

  it('reports UNPARSED for two report calls rather than choosing one', () => {
    const response = reported({ findings: [] });
    response.toolCalls.push({ name: REPORT_FINDINGS_TOOL.name, input: { findings: [FINDING] } });
    const outcome = analyzer().readToolResponse(response, FILE);
    expect(outcome.kind).toBe('unparsed');
    if (outcome.kind === 'unparsed') expect(outcome.reason).toMatch(/2 findings reports/);
  });

  it('reports UNPARSED for a call to a tool that was not offered', () => {
    const outcome = analyzer().readToolResponse(
      { stopReason: 'tool_use', toolCalls: [{ name: 'other_tool', input: { findings: [] } }], inputTokens: 1, outputTokens: 1 },
      FILE,
    );
    expect(outcome.kind).toBe('unparsed');
  });

  it('reports UNPARSED when the report holds no findings array', () => {
    for (const input of [{}, { findings: '[]' }, { findings: { 0: FINDING } }, null, [FINDING]]) {
      const outcome = analyzer().readToolResponse(reported(input), FILE);
      expect(outcome.kind, JSON.stringify(input)).toBe('unparsed');
    }
  });

  it('reports UNPARSED, not clean, when an entry is not a readable finding', () => {
    // Filtering such entries out would turn a non-empty report of malformed
    // entries into zero findings: clean, constructed from an unreadable answer.
    for (const entry of [null, 'a password on line 3', { line: 3, type: 'Password' }, { ...FINDING, severity: 7 }]) {
      const outcome = analyzer().readToolResponse(reported({ findings: [FINDING, entry] }), FILE);
      expect(outcome.kind, JSON.stringify(entry)).toBe('unparsed');
    }
  });

  it('never answers `unparsed` with an empty findings array', () => {
    // The two states must not be spelled the same way. An absence-only
    // assertion cannot tell "correctly silent" from "nothing came back".
    const outcome = analyzer().readToolResponse(
      { stopReason: 'end_turn', toolCalls: [], inputTokens: 1, outputTokens: 1 },
      FILE,
    );
    expect(outcome).not.toHaveProperty('findings');
  });
});
