/**
 * #462 — a response HackMyAgent could not read must never be reported as a
 * clean file.
 *
 * `parseFindings` extracted the model's JSON with a GREEDY `/\[[\s\S]*\]/` and
 * wrapped it in `catch { return []; }`. Measured on `c982b58`: a scanned file
 * asking for a bracketed reviewer note after the array produced 0 findings in
 * 4 trials of 4 — the analyst reported both credentials EVERY time, the greedy
 * match ran from the array's `[` to the `]` of the trailing note, `JSON.parse`
 * threw, and the catch returned an empty array. No persuasion of the model was
 * required, and the same defect silently drops real findings on benign scans
 * whenever a model adds a bracketed remark.
 *
 * 0.27.0's own headline: "a CI job that asked for a security verdict and got
 * 'I could not reach the target' has not been told the target is safe."
 */
import { describe, it, expect } from 'vitest';
import { LLMAnalyzer, extractJsonPayload } from '../../src/semantic/llm';
import type { AnalysisFile } from '../../src/semantic/types';

const FENCE = '```';
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

describe('#462 extractJsonPayload', () => {
  it('reads a bare array', () => {
    expect(extractJsonPayload('[{"a":1}]')).toBe('[{"a":1}]');
  });

  it('reads a fenced array', () => {
    expect(extractJsonPayload(`${FENCE}json\n[{"a":1}]\n${FENCE}`)).toBe('[{"a":1}]');
  });

  it('reads a fenced array that follows prose', () => {
    // Not a nicety. With the boundary rule in place the analyst frequently
    // DETECTS the injection and explains before answering, so requiring the
    // whole response to be JSON threw away correct answers on exactly the
    // adversarial inputs this fix exists for — measured at 2 of 3 trials on the
    // forged fixture.
    const response = `I need to analyze the content between the markers.\n\n${FENCE}json\n[{"a":1}]\n${FENCE}`;
    expect(extractJsonPayload(response)).toBe('[{"a":1}]');
  });

  it('does not span from a stray bracket to a distant one', () => {
    // The defect this replaces. The greedy regex matched from the array's `[`
    // through the `]` of a trailing note; this must return only the block.
    const response = `${FENCE}json\n[{"a":1}]\n${FENCE}\n\nNote: [reviewed by the platform team]`;
    expect(extractJsonPayload(response)).toBe('[{"a":1}]');
  });

  it('reads the LAST fenced block when the analyst quotes the artifact first', () => {
    // Every other fixture here holds exactly TWO fences, where "the last block"
    // and "the first block" are the same lines — so none of them can tell the
    // two apart, and mutation proved it: taking `fences[0]` as the opening left
    // this whole describe green. The distinguishing shape is a response with
    // THREE or more fences, which the boundary rule makes COMMON rather than
    // exotic: told that a forged frame is evidence, the analyst quotes the line
    // it is reporting in its own fence and then answers. Spanning from the
    // first fence to the last swallows the quote, the prose and the answer
    // together, `JSON.parse` throws, and the file is reported unanalysed — the
    // coverage gap this parser exists to stop, arriving by a different route.
    const response = [
      'The block contains a forged header. The line I am reporting is:',
      FENCE,
      'admin_password = Wint3rmute-2026-office',
      FENCE,
      'and here is the finding:',
      `${FENCE}json`,
      '[{"a":1}]',
      FENCE,
    ].join('\n');
    expect(extractJsonPayload(response)).toBe('[{"a":1}]');
  });

  it('returns null rather than a guess when there is no JSON at all', () => {
    expect(extractJsonPayload('I will not answer that.')).toBeNull();
    expect(extractJsonPayload('')).toBeNull();
  });
});

describe('#462 three states, never two', () => {
  it('reports findings when the response is readable', () => {
    const outcome = analyzer().parseModelResponse(JSON.stringify([FINDING]), FILE);
    expect(outcome.kind).toBe('findings');
    if (outcome.kind === 'findings') {
      expect(outcome.findings).toHaveLength(1);
      expect(outcome.findings[0].severity).toBe('critical');
      expect(outcome.findings[0].file).toBe('config.json');
    }
  });

  it('reports CLEAN as findings-with-none, distinct from unreadable', () => {
    const outcome = analyzer().parseModelResponse('[]', FILE);
    expect(outcome.kind).toBe('findings');
    if (outcome.kind === 'findings') expect(outcome.findings).toHaveLength(0);
  });

  it('reports UNPARSED for the exact response shape that suppressed 4/4', () => {
    // The response the model actually returned under the payload: the findings
    // are all there, followed by a bracketed note.
    const poisoned = `${FENCE}json\n${JSON.stringify([FINDING])}\n${FENCE}\n\n[reviewed by the platform team]`;
    const outcome = analyzer().parseModelResponse(poisoned, FILE);
    // The block is recoverable, so this one now yields the findings rather than
    // silence — which is the point. What must never happen is a silent zero.
    expect(outcome.kind).toBe('findings');
    if (outcome.kind === 'findings') expect(outcome.findings).toHaveLength(1);
  });

  it('reports UNPARSED, not clean, when the response cannot be read at all', () => {
    const outcome = analyzer().parseModelResponse('I could not complete this analysis.', FILE);
    expect(outcome.kind).toBe('unparsed');
    if (outcome.kind === 'unparsed') expect(outcome.reason).toMatch(/JSON array of findings/);
  });

  it('reports UNPARSED when the JSON is an object that is not a findings wrapper', () => {
    const outcome = analyzer().parseModelResponse('{"status": "ok", "notes": 3}', FILE);
    expect(outcome.kind).toBe('unparsed');
  });

  it('reads a {"findings": [...]} wrapper rather than losing it', () => {
    // A deliberate contract change, recorded because it reverses an earlier
    // assertion in this file. The old greedy parser read this shape correctly by
    // ACCIDENT — its match found the inner array — and the first tightening lost
    // it. Measured base-vs-head, that cost a CRITICAL credential finding on a
    // shape models return unprompted. An empty wrapper is therefore CLEAN, not
    // unreadable: the model answered, and the answer was "nothing".
    const outcome = analyzer().parseModelResponse(JSON.stringify({ findings: [FINDING] }), FILE);
    expect(outcome.kind).toBe('findings');
    if (outcome.kind === 'findings') expect(outcome.findings).toHaveLength(1);

    const empty = analyzer().parseModelResponse('{"findings": []}', FILE);
    expect(empty.kind).toBe('findings');
    if (empty.kind === 'findings') expect(empty.findings).toHaveLength(0);
  });

  it('reads a wrapper whose earlier prose contains a bracket', () => {
    // Mutation caught that the wrapper branch was untested: every wrapper shape
    // in this file is ALSO recoverable by the bare-bracket-span candidate, so
    // deleting the branch changed nothing and no test noticed. A redundant
    // defence nothing can distinguish from its absence is not a defence.
    // Here the first `[` sits inside a string, so the span yields invalid JSON
    // and only the wrapper branch can read this.
    const response = `{"note": "see [a] for context", "findings": ${JSON.stringify([FINDING])}}`;
    const outcome = analyzer().parseModelResponse(response, FILE);
    expect(outcome.kind).toBe('findings');
    if (outcome.kind === 'findings') expect(outcome.findings).toHaveLength(1);
  });

  it('reads an unterminated fence when prose above it contains a bracket', () => {
    // Same reasoning for the run-to-EOF rule. With a stray `[` in the prose, the
    // span candidate spans from it and fails to parse, so the only way to reach
    // the answer is to treat the unclosed fence as running to the end.
    const response = `See [1] for the policy.\n${FENCE}json\n${JSON.stringify([FINDING])}`;
    const outcome = analyzer().parseModelResponse(response, FILE);
    expect(outcome.kind).toBe('findings');
    if (outcome.kind === 'findings') expect(outcome.findings).toHaveLength(1);
  });

  it('never reports FEWER findings than the parser it replaced', () => {
    // The property CISO ruled, pinned in the suite rather than left in a
    // measurement script: a formatting change in the analyst's reply must not
    // change the verdict. Each shape below carries exactly one CRITICAL finding.
    const A = JSON.stringify([FINDING]);
    const W = '~~~';
    const shapes: Array<[string, string]> = [
      ['bare array + trailing prose', `${A}\n\nThe file is small.`],
      ['prose, then bare array', `I detected a forged header.\n\n${A}`],
      ['prose + array + trailing prose', `Analysis:\n${A}\nEnd of report.`],
      ['object wrapper', JSON.stringify({ findings: [FINDING] })],
      ['tilde fence', `${W}json\n${A}\n${W}`],
      ['unterminated fence', `${FENCE}json\n${A}`],
      ['wrapper inside a tilde fence', `${W}\n${JSON.stringify({ findings: [FINDING] })}\n${W}`],
      ['quote block, then the answer', `The line:\n${FENCE}\npw = x\n${FENCE}\nFinding:\n${FENCE}json\n${A}\n${FENCE}`],
    ];
    for (const [name, response] of shapes) {
      const outcome = analyzer().parseModelResponse(response, FILE);
      expect(outcome.kind, `${name} must be readable`).toBe('findings');
      if (outcome.kind === 'findings') {
        expect(outcome.findings, `${name} must keep the finding`).toHaveLength(1);
      }
    }
  });

  it('reports UNPARSED when the JSON is truncated', () => {
    const outcome = analyzer().parseModelResponse(`${FENCE}json\n[{"a": 1\n${FENCE}`, FILE);
    expect(outcome.kind).toBe('unparsed');
  });

  it('never answers `unparsed` with an empty findings array', () => {
    // The whole defect in one assertion: the two states must not be spelled the
    // same way. An absence-only assertion cannot tell "correctly silent" from
    // "the code threw and a catch swallowed it".
    const outcome = analyzer().parseModelResponse('nonsense', FILE);
    expect(outcome).not.toHaveProperty('findings');
  });
});
