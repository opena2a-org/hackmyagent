/**
 * The credential redaction boundary's own tests.
 *
 * WHY THIS FILE EXISTS. Before it,
 * `rg "emitFinding|redactionStatus|redactedShapes|finding-emit" __tests__/`
 * returned ONE hit and it was a docblock comment. Making `RedactionPass.run`
 * (`src/hardening/finding-emit.ts`) a pass-through — which disables ALL
 * redaction on every field of every finding — left 4035/4035 tests green. Two
 * independent reviewers demonstrated that separately. Every defect in the
 * boundary was therefore unfalsifiable, and any fix written against it was a fix
 * nobody could check.
 *
 * RED-PROOF. Each block names, in a comment, the exact implementation line whose
 * reversion turns it red. That is the property being bought here: not coverage,
 * but the ability of this file to notice.
 *
 * The tests run in-process (no spawn) so they are fast, are not gated behind a
 * `skipIf(builtArtifactsExist)` that would let them run nowhere on a merge, and
 * can be mutation-checked cheaply.
 *
 * Credential values are synthesised at runtime from a repeated character, never
 * written as literals, so nothing here trips push protection or a secret
 * scanner (the idiom `config-credential-depth.test.ts` established).
 */
import { describe, it, expect } from 'vitest';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { emitFinding, emitFindings } from '../../src/hardening/finding-emit';
import { HardeningScanner } from '../../src/hardening/scanner';
import { mergeFindings } from '../../src/nanomind-core/scanner-bridge';
import type { SecurityFindingDraft } from '../../src/hardening/security-check';
import type { Evidence } from '../../src/types/finding-evidence';

/** Synthesised at runtime — never a literal in the source tree. */
const GH = `ghp_${'a'.repeat(36)}`;
const AWS = `AKIA${'B'.repeat(16)}`;
const GH_MARK = '[REDACTED_GITHUB_TOKEN]';
const AWS_MARK = '[REDACTED_AWS_KEY]';

function draft(over: Record<string, unknown> = {}): SecurityFindingDraft {
  return {
    checkId: 'TEST-EMIT-001',
    name: 'name',
    description: 'description',
    category: 'credentials',
    severity: 'high',
    passed: false,
    message: 'message',
    fixable: false,
    ...over,
  } as unknown as SecurityFindingDraft;
}

/**
 * The seven byte-carrying fields, spelled out here rather than imported.
 *
 * `BYTE_CARRYING_FIELDS` is module-private, and that is deliberate: a test that
 * imported the implementation's own list could not notice a field being dropped
 * FROM it, which is the thing most worth noticing. So this list is an
 * independent statement of the contract, and deleting any entry from the
 * implementation turns exactly one case below red.
 *
 * It does NOT close the other direction — a NEW string field added to
 * `SecurityFinding` and not added to the implementation list is unredacted and
 * invisible to this file. That is deferred defect (8), compiler-enforced
 * completeness, and it is a real hole until it lands.
 */
const BYTE_CARRYING = [
  'name',
  'message',
  'description',
  'fix',
  'manualFix',
  'guidance',
  'fixMessage',
] as const;

describe('emitFinding — the seven byte-carrying fields', () => {
  // RED-PROOF: delete the field's entry from `BYTE_CARRYING_FIELDS`
  // (finding-emit.ts:59-67), or make `RedactionPass.run` return `value`.
  for (const field of BYTE_CARRYING) {
    it(`${field}: credential is gone, status is applied, shape is resolved`, () => {
      const emitted = emitFinding(draft({ [field]: `prefix ${GH} suffix` }));
      const value = (emitted as unknown as Record<string, string>)[field];

      expect(value).not.toContain(GH);
      expect(value).toContain(GH_MARK);
      expect(emitted.redactionStatus).toBe('applied');
      expect(emitted.redactedShapes).toEqual(['github-pat']);
    });
  }

  it('a finding with no credential anywhere reports clean with no shapes', () => {
    const emitted = emitFinding(draft({ message: 'nothing sensitive here' }));
    expect(emitted.redactionStatus).toBe('clean');
    expect(emitted.redactedShapes).toEqual([]);
  });

  /**
   * Pins the ORDER AND DEDUP a consumer sees, not the `.sort()` in
   * `emitFinding`: `RedactionPass.resolvedShapes` already sorts within a pass,
   * so this stays green if that second sort is deleted. The merge-level sort is
   * pinned by `shapes accumulate across passes` below. Measured, not assumed —
   * a mutation run removing each sort separately established which test catches
   * which, and the two are not redundant.
   */
  it('shapes a consumer sees are sorted and deduped across fields', () => {
    const emitted = emitFinding(
      draft({ message: `${GH} and ${AWS}`, description: `again ${GH}` }),
    );
    // Sorted: 'aws-access-key-id' < 'github-pat'. Deduped: one github-pat.
    expect(emitted.redactedShapes).toEqual(['aws-access-key-id', 'github-pat']);
    expect(emitted.message).toContain(GH_MARK);
    expect(emitted.message).toContain(AWS_MARK);
  });

  it('does not mutate the draft it was handed', () => {
    const original = draft({ message: `tok ${GH}` });
    const emitted = emitFinding(original);
    expect(original.message).toContain(GH);
    expect(emitted.message).not.toContain(GH);
  });
});

describe('emitFinding — every Evidence leaf', () => {
  // Each case plants the credential in exactly ONE leaf, so reverting one
  // `pass.run(...)` in `redactEvidence` turns exactly one case red.

  // RED-PROOF: finding-emit.ts:101 `content: pass.run(l.content)`
  it('positive.lines[].content', () => {
    const evidence: Evidence = {
      kind: 'positive',
      lines: [{ n: 1, content: `token ${GH}`, why: 'clean prose' }],
    };
    const emitted = emitFinding(draft({ evidence }));
    const out = emitted.evidence as Extract<Evidence, { kind: 'positive' }>;
    expect(out.lines[0].content).not.toContain(GH);
    expect(out.lines[0].content).toContain(GH_MARK);
    expect(emitted.redactionStatus).toBe('applied');
    expect(emitted.redactedShapes).toEqual(['github-pat']);
  });

  // RED-PROOF: finding-emit.ts:102 `why: pass.run(l.why)`
  it('positive.lines[].why', () => {
    const evidence: Evidence = {
      kind: 'positive',
      lines: [{ n: 1, content: 'clean prose', why: `because ${GH}` }],
    };
    const emitted = emitFinding(draft({ evidence }));
    const out = emitted.evidence as Extract<Evidence, { kind: 'positive' }>;
    expect(out.lines[0].why).not.toContain(GH);
    expect(out.lines[0].why).toContain(GH_MARK);
    expect(emitted.redactionStatus).toBe('applied');
  });

  // RED-PROOF: finding-emit.ts:109 `content: pass.run(l.content)`
  it('absence.observed.lines[].content', () => {
    const evidence: Evidence = {
      kind: 'absence',
      observed: { lines: [{ n: 2, content: `key ${GH}` }], summary: 'clean' },
      expected: [{ constraint: 'trust-hierarchy', rationale: 'clean' }],
    };
    const emitted = emitFinding(draft({ evidence }));
    const out = emitted.evidence as Extract<Evidence, { kind: 'absence' }>;
    expect(out.observed.lines[0].content).not.toContain(GH);
    expect(out.observed.lines[0].content).toContain(GH_MARK);
    expect(emitted.redactionStatus).toBe('applied');
  });

  // RED-PROOF: finding-emit.ts:110 `summary: pass.run(evidence.observed.summary)`
  it('absence.observed.summary', () => {
    const evidence: Evidence = {
      kind: 'absence',
      observed: { lines: [{ n: 2, content: 'clean' }], summary: `holds ${GH}` },
      expected: [{ constraint: 'trust-hierarchy', rationale: 'clean' }],
    };
    const emitted = emitFinding(draft({ evidence }));
    const out = emitted.evidence as Extract<Evidence, { kind: 'absence' }>;
    expect(out.observed.summary).not.toContain(GH);
    expect(out.observed.summary).toContain(GH_MARK);
    expect(emitted.redactionStatus).toBe('applied');
  });

  // RED-PROOF: finding-emit.ts:119 `rationale: pass.run(e.rationale)`
  it('absence.expected[].rationale', () => {
    const evidence: Evidence = {
      kind: 'absence',
      observed: { lines: [{ n: 2, content: 'clean' }], summary: 'clean' },
      expected: [{ constraint: 'trust-hierarchy', rationale: `see ${GH}` }],
    };
    const emitted = emitFinding(draft({ evidence }));
    const out = emitted.evidence as Extract<Evidence, { kind: 'absence' }>;
    expect(out.expected[0].rationale).not.toContain(GH);
    expect(out.expected[0].rationale).toContain(GH_MARK);
    expect(emitted.redactionStatus).toBe('applied');
  });

  // RED-PROOF: finding-emit.ts:127 (mixed positive content)
  it('mixed.positive.lines[].content', () => {
    const evidence: Evidence = {
      kind: 'mixed',
      positive: { lines: [{ n: 1, content: `tok ${GH}`, why: 'clean' }] },
      absence: {
        observed: { lines: [{ n: 2, content: 'clean' }], summary: 'clean' },
        expected: [{ constraint: 'c', rationale: 'clean' }],
      },
    };
    const emitted = emitFinding(draft({ evidence }));
    const out = emitted.evidence as Extract<Evidence, { kind: 'mixed' }>;
    expect(out.positive.lines[0].content).not.toContain(GH);
    expect(out.positive.lines[0].content).toContain(GH_MARK);
    expect(emitted.redactionStatus).toBe('applied');
  });

  // RED-PROOF: finding-emit.ts:128 (mixed positive why)
  it('mixed.positive.lines[].why', () => {
    const evidence: Evidence = {
      kind: 'mixed',
      positive: { lines: [{ n: 1, content: 'clean', why: `why ${GH}` }] },
      absence: {
        observed: { lines: [{ n: 2, content: 'clean' }], summary: 'clean' },
        expected: [{ constraint: 'c', rationale: 'clean' }],
      },
    };
    const emitted = emitFinding(draft({ evidence }));
    const out = emitted.evidence as Extract<Evidence, { kind: 'mixed' }>;
    expect(out.positive.lines[0].why).not.toContain(GH);
    expect(out.positive.lines[0].why).toContain(GH_MARK);
    expect(emitted.redactionStatus).toBe('applied');
  });

  // RED-PROOF: finding-emit.ts:136 (mixed absence observed content)
  it('mixed.absence.observed.lines[].content', () => {
    const evidence: Evidence = {
      kind: 'mixed',
      positive: { lines: [{ n: 1, content: 'clean', why: 'clean' }] },
      absence: {
        observed: { lines: [{ n: 2, content: `tok ${GH}` }], summary: 'clean' },
        expected: [{ constraint: 'c', rationale: 'clean' }],
      },
    };
    const emitted = emitFinding(draft({ evidence }));
    const out = emitted.evidence as Extract<Evidence, { kind: 'mixed' }>;
    expect(out.absence.observed.lines[0].content).not.toContain(GH);
    expect(out.absence.observed.lines[0].content).toContain(GH_MARK);
    expect(emitted.redactionStatus).toBe('applied');
  });

  // RED-PROOF: finding-emit.ts:138 (mixed absence summary)
  it('mixed.absence.observed.summary', () => {
    const evidence: Evidence = {
      kind: 'mixed',
      positive: { lines: [{ n: 1, content: 'clean', why: 'clean' }] },
      absence: {
        observed: { lines: [{ n: 2, content: 'clean' }], summary: `sum ${GH}` },
        expected: [{ constraint: 'c', rationale: 'clean' }],
      },
    };
    const emitted = emitFinding(draft({ evidence }));
    const out = emitted.evidence as Extract<Evidence, { kind: 'mixed' }>;
    expect(out.absence.observed.summary).not.toContain(GH);
    expect(out.absence.observed.summary).toContain(GH_MARK);
    expect(emitted.redactionStatus).toBe('applied');
  });

  // RED-PROOF: finding-emit.ts:142 (mixed absence expected rationale)
  it('mixed.absence.expected[].rationale', () => {
    const evidence: Evidence = {
      kind: 'mixed',
      positive: { lines: [{ n: 1, content: 'clean', why: 'clean' }] },
      absence: {
        observed: { lines: [{ n: 2, content: 'clean' }], summary: 'clean' },
        expected: [{ constraint: 'c', rationale: `rat ${GH}` }],
      },
    };
    const emitted = emitFinding(draft({ evidence }));
    const out = emitted.evidence as Extract<Evidence, { kind: 'mixed' }>;
    expect(out.absence.expected[0].rationale).not.toContain(GH);
    expect(out.absence.expected[0].rationale).toContain(GH_MARK);
    expect(emitted.redactionStatus).toBe('applied');
  });
});

describe('emitFinding — rationale.plainEnglish', () => {
  // RED-PROOF: finding-emit.ts:231. This field is NOT in the settlement brief's
  // field list; `finding-adapter.ts` assigns the same string to `message` and to
  // `rationale.plainEnglish`, so dropping this line leaves the identical bytes
  // on a second field of the same object.
  it('is redacted, and the status reflects it', () => {
    const emitted = emitFinding(
      draft({ rationale: { plainEnglish: `in plain English, ${GH}` } }),
    );
    expect(emitted.rationale?.plainEnglish).not.toContain(GH);
    expect(emitted.rationale?.plainEnglish).toContain(GH_MARK);
    expect(emitted.redactionStatus).toBe('applied');
    expect(emitted.redactedShapes).toEqual(['github-pat']);
  });
});

describe('emitFinding — details is an open bag, redacted at any depth', () => {
  /** `{ root: <token nested `depth` containers deep> }`. */
  function nestObjects(depth: number): Record<string, unknown> {
    let v: unknown = `embedded ${GH}`;
    for (let i = 0; i < depth; i++) v = { nest: v };
    return { root: v };
  }

  function nestArrays(depth: number): Record<string, unknown> {
    let v: unknown = `embedded ${GH}`;
    for (let i = 0; i < depth; i++) v = [v];
    return { root: v };
  }

  // RED-PROOF: finding-emit.ts:168 `if (typeof value === 'string') return pass.run(value)`.
  it('depth 1: string leaf is redacted', () => {
    const emitted = emitFinding(draft({ details: nestObjects(1) }));
    expect(JSON.stringify(emitted.details)).not.toContain(GH);
    expect(JSON.stringify(emitted.details)).toContain(GH_MARK);
    expect(emitted.redactionStatus).toBe('applied');
    expect(emitted.redactedShapes).toEqual(['github-pat']);
  });

  it('depth 12: the last depth the cap admits is still redacted', () => {
    const emitted = emitFinding(draft({ details: nestObjects(12) }));
    expect(JSON.stringify(emitted.details)).not.toContain(GH);
    expect(emitted.redactionStatus).toBe('applied');
  });

  /**
   * DEFECT (1) — the release-blocking one. This case FAILS before the fix.
   *
   * The depth cap short-circuits at a CONTAINER, so strings inside that
   * container are never offered to the redactor: `details` nested 13 deep
   * published a verbatim token AND asserted `redactionStatus: 'clean'` over it.
   * A false affirmative of cleanliness is the exact failure this boundary
   * exists to end, which is why the leak and the status are asserted together.
   *
   * RED-PROOF: restore `if (depth > 12) return value;` at finding-emit.ts:172.
   */
  it('depth 13 (objects): no leak, and the status is never a false clean', () => {
    const emitted = emitFinding(draft({ details: nestObjects(13) }));
    expect(JSON.stringify(emitted.details)).not.toContain(GH);
    expect(emitted.redactionStatus).not.toBe('clean');
  });

  it('depth 13 (arrays): no leak, and the status is never a false clean', () => {
    const emitted = emitFinding(draft({ details: nestArrays(13) }));
    expect(JSON.stringify(emitted.details)).not.toContain(GH);
    expect(emitted.redactionStatus).not.toBe('clean');
  });

  it('depth 40: a deeply nested bag still leaks nothing', () => {
    const emitted = emitFinding(draft({ details: nestObjects(40) }));
    expect(JSON.stringify(emitted.details)).not.toContain(GH);
    expect(emitted.redactionStatus).not.toBe('clean');
  });

  it('a self-referential details bag terminates and leaks nothing', () => {
    const cycle: Record<string, unknown> = { token: `cyc ${GH}` };
    cycle.self = cycle;
    const emitted = emitFinding(draft({ details: cycle }));
    expect(JSON.stringify(emitted.details, cycleSafe())).not.toContain(GH);
    expect(emitted.redactionStatus).not.toBe('clean');
  });

  it('a non-plain object in details is passed through, not flattened to {}', () => {
    const when = new Date('2026-01-01T00:00:00.000Z');
    const emitted = emitFinding(draft({ details: { when } }));
    expect((emitted.details as { when: Date }).when).toBeInstanceOf(Date);
  });
});

/** JSON.stringify replacer that tolerates cycles, so the assertion can run. */
function cycleSafe() {
  const seen = new WeakSet<object>();
  return (_k: string, v: unknown) => {
    if (typeof v === 'object' && v !== null) {
      if (seen.has(v as object)) return '[cycle]';
      seen.add(v as object);
    }
    return v;
  };
}

describe('emitFinding — applied is absorbing across passes', () => {
  /**
   * Redaction is idempotent on TEXT (a marker matches no rule) but NOT on the
   * status: a second pass finds nothing to change and would conclude 'clean'
   * for a finding that really was redacted. Several producers are public
   * exports whose output is rebuilt by an internal caller, so the second pass
   * is a live path, not a hypothetical.
   *
   * RED-PROOF: finding-emit.ts:237 — replace `priorApplied ? 'applied' : pass.status`
   * with `pass.status`.
   */
  it('re-emitting an already-applied finding does not downgrade to clean', () => {
    const once = emitFinding(draft({ message: `tok ${GH}` }));
    expect(once.redactionStatus).toBe('applied');

    const twice = emitFinding(once);
    expect(twice.redactionStatus).toBe('applied');
    expect(twice.redactedShapes).toEqual(['github-pat']);
  });

  // RED-PROOF: finding-emit.ts:238-240 — drop `...priorShapes` from the merge.
  it('shapes accumulate across passes rather than being replaced', () => {
    const once = emitFinding(draft({ message: `tok ${GH}` }));
    const twice = emitFinding({ ...once, description: `also ${AWS}` } as never);
    expect(twice.redactedShapes).toEqual(['aws-access-key-id', 'github-pat']);
    expect(twice.redactionStatus).toBe('applied');
  });

  it('emitFindings applies the same boundary per element', () => {
    const out = emitFindings([
      draft({ message: `a ${GH}` }),
      draft({ message: 'b clean' }),
    ]);
    expect(out[0].message).not.toContain(GH);
    expect(out[0].redactionStatus).toBe('applied');
    expect(out[1].redactionStatus).toBe('clean');
  });
});

describe('emitFinding — an unrecognised evidence kind fails CLOSED', () => {
  /**
   * DEFECT (3) — FAILS before the fix.
   *
   * `redactEvidence`'s switch has no `default`, so an unrecognised
   * `evidence.kind` returns `undefined`: the evidence is silently DELETED and
   * the finding still reports 'clean'. It fails open in both directions at
   * once, and it is reachable through the public `ScanOptions.semanticPass`
   * hook, so the unrecognised kind is attacker-adjacent rather than theoretical.
   *
   * RED-PROOF: delete the `default:` arm from `redactEvidence`.
   */
  const future = {
    kind: 'future-variant',
    note: `carries ${GH}`,
    nested: { deeper: [`also ${AWS}`] },
  } as unknown as Evidence;

  it('does not delete the evidence', () => {
    const emitted = emitFinding(draft({ evidence: future }));
    expect(emitted.evidence).toBeDefined();
  });

  it('redacts every string leaf of the unknown shape', () => {
    const emitted = emitFinding(draft({ evidence: future }));
    const serialized = JSON.stringify(emitted.evidence);
    expect(serialized).not.toContain(GH);
    expect(serialized).not.toContain(AWS);
    expect(serialized).toContain(GH_MARK);
  });

  it('does not report clean over an unexamined shape', () => {
    const emitted = emitFinding(draft({ evidence: future }));
    expect(emitted.redactionStatus).not.toBe('clean');
  });

  it('preserves the discriminant so a consumer can still branch', () => {
    const emitted = emitFinding(draft({ evidence: future }));
    expect((emitted.evidence as unknown as { kind: string }).kind).toBe('future-variant');
  });
});

describe('emitFinding — malformed evidence does not abort the scan', () => {
  /**
   * DEFECT (4) — FAILS before the fix.
   *
   * Malformed `absence`/`mixed` evidence THROWS inside `redactEvidence`, and
   * `scanner.ts`'s return has no try/catch, so the throw aborts the WHOLE scan.
   * The same input was inert before this change: a crash introduced by the
   * boundary is strictly worse than the leak it was added to close.
   *
   * RED-PROOF: remove the optional chaining from the four sub-field reads.
   */
  const malformed: Array<[string, unknown]> = [
    ['absence missing observed', { kind: 'absence', expected: [] }],
    ['absence missing observed.lines', { kind: 'absence', observed: { summary: 's' }, expected: [] }],
    ['absence missing expected', { kind: 'absence', observed: { lines: [], summary: 's' } }],
    ['mixed missing positive', { kind: 'mixed', absence: { observed: { lines: [], summary: 's' }, expected: [] } }],
    ['mixed missing positive.lines', { kind: 'mixed', positive: {}, absence: { observed: { lines: [], summary: 's' }, expected: [] } }],
    ['mixed missing absence', { kind: 'mixed', positive: { lines: [] } }],
    ['mixed missing absence.observed', { kind: 'mixed', positive: { lines: [] }, absence: { expected: [] } }],
    ['mixed missing absence.expected', { kind: 'mixed', positive: { lines: [] }, absence: { observed: { lines: [], summary: 's' } } }],
    ['positive missing lines', { kind: 'positive' }],

    // A list sub-field of the WRONG TYPE, not merely absent. `?? []` guards
    // null and undefined only, so these still reached `.map` and threw — the
    // same abort-the-whole-scan failure, one step further out. Found by probing
    // the first version of this fix rather than by reasoning about it.
    ['positive.lines is a number', { kind: 'positive', lines: 42 }],
    ['absence.observed.lines is a string', { kind: 'absence', observed: { lines: 'oops', summary: 's' }, expected: [] }],
    ['absence.expected is a string', { kind: 'absence', observed: { lines: [], summary: 's' }, expected: 'oops' }],
    ['mixed.positive.lines is an object', { kind: 'mixed', positive: { lines: {} }, absence: { observed: { lines: [], summary: 's' }, expected: [] } }],
    ['mixed.absence.expected is a number', { kind: 'mixed', positive: { lines: [] }, absence: { observed: { lines: [], summary: 's' }, expected: 7 } }],
    ['absence.observed is a string', { kind: 'absence', observed: 'oops', expected: [] }],
  ];

  for (const [label, evidence] of malformed) {
    it(`${label}: emits instead of throwing`, () => {
      expect(() =>
        emitFinding(draft({ evidence: evidence as Evidence })),
      ).not.toThrow();
    });
  }

  it('a malformed shape that still carries a credential does not leak it', () => {
    const emitted = emitFinding(
      draft({
        evidence: {
          kind: 'absence',
          observed: { summary: `sum ${GH}` },
        } as unknown as Evidence,
      }),
    );
    expect(JSON.stringify(emitted.evidence)).not.toContain(GH);
    expect(emitted.redactionStatus).not.toBe('clean');
  });
});

describe('mergeFindings — the route point that actually covers `check`', () => {
  /**
   * `check --json` returns BEFORE the text renderer runs, so the `emitFindings`
   * call in the renderer cannot be what covers it. What covers it is
   * `astFindingToSecurityFinding` calling `emitFinding` inside `mergeFindings`
   * (`scanner-bridge.ts`), and on `check`'s path the static-findings argument is
   * empty, so EVERY element of the merged array comes from that constructor.
   *
   * That is a load-bearing accident: nothing in `cli.ts` requires it and, until
   * this block, nothing would have noticed its removal. Pinning the mechanism
   * rather than the command is deliberate — it is the assertion that stays true
   * if the CLI is restructured, and it red-proofs by making the `emitFinding`
   * call at that route point a pass-through.
   */
  function astFinding(over: Record<string, unknown> = {}) {
    return {
      checkId: 'AST-CRED-001',
      name: `token ${GH}`,
      description: `description ${GH}`,
      category: 'credentials',
      severity: 'high' as const,
      passed: false,
      message: `message ${GH}`,
      fixable: false,
      file: 'config.json',
      ...over,
    };
  }

  it('every merged finding has crossed the boundary when the static set is empty', () => {
    const merged = mergeFindings([], [astFinding(), astFinding({ checkId: 'AST-CRED-003' })]);

    expect(merged.length).toBe(2);
    for (const f of merged) {
      const emitted = f as unknown as { redactionStatus?: string; redactedShapes?: string[] };
      expect(emitted.redactionStatus).toBeDefined();
      expect(emitted.redactionStatus).toBe('applied');
      expect(emitted.redactedShapes).toEqual(['github-pat']);
    }
  });

  it('no credential survives into the merged array', () => {
    const merged = mergeFindings([], [astFinding()]);
    expect(JSON.stringify(merged)).not.toContain(GH);
    expect(JSON.stringify(merged)).toContain(GH_MARK);
  });

  /**
   * The absorbing-applied guard is only reachable if the two fields SURVIVE
   * whatever rebuilds a finding between passes. A re-map that lists its fields
   * by name and omits them defeats the guard by construction rather than by a
   * cast, and the second pass then reports `'clean'` over text that really was
   * redacted — defect (1)'s false-affirmative failure, arriving by a different
   * road. This pins the property the guard depends on.
   */
  it('a rebuild that preserves the two fields keeps an honest applied', () => {
    const [first] = mergeFindings([], [astFinding()]) as unknown as Array<
      Record<string, unknown>
    >;
    expect(first.redactionStatus).toBe('applied');

    const rebuiltPreservingFields = emitFinding({
      ...(first as unknown as SecurityFindingDraft),
      redactionStatus: first.redactionStatus,
      redactedShapes: first.redactedShapes,
    } as unknown as SecurityFindingDraft);

    expect(rebuiltPreservingFields.redactionStatus).toBe('applied');
    expect(rebuiltPreservingFields.redactedShapes).toEqual(['github-pat']);
  });
});

describe('scan() — the emitted document carries no credential on any channel', () => {
  /**
   * The boundary's whole point is the published document, not the unit. This
   * runs the real scanner over a tree with a planted token and asserts the
   * credential appears NOWHERE in the serialized result — which is what
   * `--json` publishes, and it covers `findings` and `allFindings` together
   * (two of the four measured JSON leak paths were under `$.allFindings[…]`).
   *
   * In-process rather than spawning the built CLI: a spawn suite has to be
   * gated on the build existing, and a gated assertion runs nowhere on a merge.
   * (Stated without naming the built entry point, because the #285 harness gate
   * treats ANY mention of that path as evidence a suite spawns it. The gate is
   * deliberately crude and adding an exemption to it would widen it into a
   * bypass, so the prose moves instead of the gate.)
   */
  async function scanTreeWithPlantedToken() {
    const dir = await mkdtemp(path.join(tmpdir(), 'hma-emit-'));
    await writeFile(path.join(dir, 'package.json'), '{"name":"e","version":"1.0.0"}\n');
    await writeFile(path.join(dir, 'config.json'), JSON.stringify({ token: GH }) + '\n');
    const scanner = new HardeningScanner();
    const result = await scanner.scan({ targetDir: dir, autoFix: false });
    return { dir, result };
  }

  it('no raw credential survives into the serialized scan result', async () => {
    const { dir, result } = await scanTreeWithPlantedToken();
    try {
      expect(JSON.stringify(result)).not.toContain(GH);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('every emitted finding carries the two redaction fields', async () => {
    const { dir, result } = await scanTreeWithPlantedToken();
    try {
      const all = [...result.findings, ...(result.allFindings ?? [])];
      expect(all.length).toBeGreaterThan(0);
      for (const f of all) {
        expect(['applied', 'clean', 'unverified']).toContain(f.redactionStatus);
        expect(Array.isArray(f.redactedShapes)).toBe(true);
      }
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  /**
   * `emitOnce` memoizes on the DRAFT, so a draft reaching both channels yields
   * one emitted object, by reference. Without it, `findings` and `allFindings`
   * hold twin objects, and a later per-object mutation applies to one channel
   * only.
   *
   * RED-PROOF: replace `emitOnce` with `emitFinding` at scanner.ts:3368/3379 —
   * the reference overlap drops to zero while every other assertion stays green.
   */
  it('emitOnce gives findings and allFindings the same objects by identity', async () => {
    const { dir, result } = await scanTreeWithPlantedToken();
    try {
      const all = result.allFindings ?? [];
      expect(all.length).toBeGreaterThan(0);

      const overlapByValue = result.findings.filter((f) =>
        all.some(
          (a) => a.checkId === f.checkId && a.file === f.file && a.line === f.line,
        ),
      );
      expect(overlapByValue.length).toBeGreaterThan(0);

      // Every finding present in both channels is the SAME object.
      const overlapByIdentity = result.findings.filter((f) => all.includes(f));
      expect(overlapByIdentity.length).toBe(overlapByValue.length);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
