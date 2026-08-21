/**
 * Unit 2 of the redaction-boundary hardening: defects (10) + (13).
 *
 * (10) `redactionStatus` was a write-only guarantee — nothing read it at any
 * publish boundary. `assertRedactionProvenance` is the read; these tests prove
 * it throws on a laundered finding and fires on ZERO healthy objects.
 *
 * (13) a named-field rebuild drops the two redaction fields and re-emits, so an
 * honest `'applied'` is downgraded to `'clean'` — invisible to grep because a
 * stripped draft is indistinguishable from a fresh one. `reemitFinding` is the
 * sanctioned rebuild; its parameter types make the drop unrepresentable.
 *
 * RED-PROOF. Each block names the exact implementation property whose reversion
 * turns it red. The dropping-rebuild case below is a MECHANISM CONTROL, not a
 * defect pin: it measures the hazard the helper exists to prevent, so the
 * green elsewhere is non-vacuous. Canaries are synthesised at runtime — never
 * a literal in the source tree (the idiom finding-emit.test.ts:35-39 uses).
 */
import { describe, it, expect } from 'vitest';
import {
  emitFinding,
  emitFindings,
  reemitFinding,
  assertRedactionProvenance,
  RedactionProvenanceError,
  redactOpenBagForPublish,
} from '../../src/hardening/finding-emit';
import type { SecurityFinding, SecurityFindingDraft } from '../../src/hardening/security-check';

/** Synthesised at runtime — never a literal in the source tree. */
const GH = `ghp_${'a'.repeat(36)}`;
const AWS = `AKIA${'B'.repeat(16)}`;
const GH_MARK = '[REDACTED_GITHUB_TOKEN]';

function draft(over: Record<string, unknown> = {}): SecurityFindingDraft {
  return {
    checkId: 'TEST-READER-001',
    name: 'reader test finding',
    description: 'a finding used to exercise the publish-boundary reader',
    category: 'credentials',
    severity: 'high',
    passed: false,
    message: 'reader test message',
    fixable: false,
    ...over,
  } as unknown as SecurityFindingDraft;
}

/** An emitted finding carrying an honest 'applied' — the precondition most
 * cases below rest on, asserted once so no case is vacuous. */
function appliedFinding(): SecurityFinding {
  const f = emitFinding(draft({ message: `token ${GH}` }));
  expect(f.redactionStatus, 'precondition: canary must be detected').toBe('applied');
  expect(f.redactedShapes, 'precondition: shape must resolve').toContain('github-pat');
  expect(JSON.stringify(f), 'precondition: emit must strip the bytes').not.toContain(GH);
  return f;
}

/** The launder: strip the two fields off an emitted finding, the way any
 * named-field rebuild does. Enumerates every OTHER field on purpose. */
function stripped(f: SecurityFinding): Record<string, unknown> {
  const { redactionStatus: _s, redactedShapes: _h, ...rest } = f as SecurityFinding &
    Record<string, unknown>;
  return rest;
}

describe('reemitFinding — the sanctioned rebuild preserves provenance', () => {
  // RED-PROOF: finding-emit.ts `reemitFinding` — replace `{ ...prior, ...overrides }`
  // with a named-field enumeration of the draft fields. This case then reads
  // 'clean' and goes red.
  it('preserves an honest applied through a normalizing rebuild', () => {
    const first = appliedFinding();
    const second = reemitFinding(first, {
      checkId: first.checkId || '',
      name: first.name || first.description || '',
      message: first.message || first.description || '',
    });
    expect(second.redactionStatus).toBe('applied');
    expect(second.redactedShapes).toContain('github-pat');
  });

  it('accumulates shapes when an override introduces new credential bytes', () => {
    const first = appliedFinding();
    const second = reemitFinding(first, { description: `and also ${AWS}` });
    expect(second.redactionStatus).toBe('applied');
    expect(second.redactedShapes).toEqual(
      expect.arrayContaining(['github-pat', 'aws-access-key-id']),
    );
    expect(JSON.stringify(second)).not.toContain(AWS);
  });

  // RED-PROOF: delete the runtime destructure of `redactionStatus` /
  // `redactedShapes` from `reemitFinding` — this case goes red.
  //
  // The `Omit` on the override parameter is not sufficient on its own:
  // TypeScript's excess-property check applies to LITERAL bags, so a widened
  // variable carrying `redactionStatus: 'clean'` typechecks, reaches the
  // spread, and downgrades a prior 'applied' — defect (13) reintroduced
  // through the sanctioned helper, and invisible to the publish reader
  // because 'clean' is a valid publish status. Found by adversarial review
  // 2026-08-21 (F1), which built exactly this bag and compiled it.
  it('a widened override bag cannot smuggle a status downgrade', () => {
    const first = appliedFinding();
    const smuggle: Record<string, unknown> = {
      passed: false,
      redactionStatus: 'clean',
      redactedShapes: [],
    };
    const second = reemitFinding(first, smuggle);
    expect(second.redactionStatus, 'the prior applied must survive a hostile override bag').toBe('applied');
    expect(second.redactedShapes).toContain('github-pat');
  });

  // MECHANISM CONTROL, not a defect pin — this is defect (13) itself, measured,
  // so the preserving cases above are provably non-vacuous. It passes on every
  // tree because it exercises the hazard, not the fix: `emitFinding` cannot
  // distinguish a stripped rebuild from a fresh draft. That is WHY rebuilds
  // must go through `reemitFinding`; nothing weaker is testable.
  it('control: a named-field rebuild that drops the two fields downgrades applied to clean', () => {
    const first = appliedFinding();
    const relaundered = emitFindings([stripped(first) as unknown as SecurityFindingDraft])[0];
    expect(relaundered.redactionStatus, 'the defect-13 mechanism must be live for these tests to mean anything').toBe('clean');
    expect(relaundered.redactedShapes).toEqual([]);
  });
});

describe('assertRedactionProvenance — the publish-boundary read', () => {
  // RED-PROOF: finding-emit.ts `assertRedactionProvenance` — delete the
  // `status !== 'applied' && status !== 'clean'` throw. Every case in this
  // block except the zero-fire controls goes red.
  it('throws on a stripped finding at the top level of a payload', () => {
    const laundered = stripped(appliedFinding());
    expect(() => assertRedactionProvenance([laundered], 'test-channel')).toThrow(
      RedactionProvenanceError,
    );
  });

  it('throws on a stripped finding nested inside objects and arrays', () => {
    const laundered = stripped(appliedFinding());
    const payload = { report: { sections: [{ items: [{ wrapped: laundered }] }] } };
    expect(() => assertRedactionProvenance(payload, 'test-channel')).toThrow(
      RedactionProvenanceError,
    );
  });

  // RED-PROOF: reintroduce a depth cap that `continue`s on deep containers —
  // this case goes red. The walk must have NO silent skip (defect (1)'s class).
  it('throws on a stripped finding buried 500 containers deep', () => {
    const laundered = stripped(appliedFinding());
    let payload: unknown = laundered;
    for (let i = 0; i < 500; i++) payload = { deeper: [payload] };
    expect(() => assertRedactionProvenance(payload, 'test-channel')).toThrow(
      RedactionProvenanceError,
    );
  });

  it('names the channel and checkId, and carries none of the finding text', () => {
    const laundered = stripped(
      emitFinding(draft({ message: `token ${GH}`, description: `desc ${GH}` })),
    );
    // The launder keeps the redacted text; simulate the worst case — a finding
    // whose bytes were NEVER redacted — by planting the canary directly.
    laundered.message = `raw ${GH}`;
    let thrown: unknown;
    try {
      assertRedactionProvenance({ findings: [laundered] }, 'registry-publish');
    } catch (e) {
      thrown = e;
    }
    expect(thrown).toBeInstanceOf(RedactionProvenanceError);
    const err = thrown as RedactionProvenanceError;
    expect(err.message).toContain('registry-publish');
    expect(err.message).toContain('TEST-READER-001');
    expect(err.message, 'the error must not republish the bytes it exists to contain').not.toContain(GH);
  });

  // RED-PROOF: allow 'unverified' through the status check — goes red.
  // [CHIEF-CISO] 2026-08-21: 'unverified' may exist in process, it may never
  // cross a publish boundary.
  it("throws on redactionStatus 'unverified' at a publish boundary", () => {
    const f = { ...appliedFinding(), redactionStatus: 'unverified' };
    expect(() => assertRedactionProvenance([f], 'test-channel')).toThrow(
      RedactionProvenanceError,
    );
  });

  // RED-PROOF: delete the `Array.isArray(value.redactedShapes)` throw — goes red.
  it('throws when redactedShapes is missing even with a valid status', () => {
    const f: Record<string, unknown> = { ...stripped(appliedFinding()), redactionStatus: 'clean' };
    expect(() => assertRedactionProvenance([f], 'test-channel')).toThrow(
      RedactionProvenanceError,
    );
  });

  it('zero-fire control: an honestly emitted finding passes', () => {
    const payload = { findings: emitFindings([draft(), draft({ message: `x ${GH}` })]) };
    expect(() => assertRedactionProvenance(payload, 'test-channel')).not.toThrow();
  });

  // The exemption mechanism is the SHAPE predicate, never a site allowlist
  // ([CHIEF-CISO] condition). The pair below are complementary on purpose: the
  // same row, with and without the fields that make it finding-shaped. If the
  // predicate drifts, one of the two goes red — the filters must negate.
  it('exempts an identity-only projection row (no passed, no body text) by shape', () => {
    const identityRow = { checkId: 'PROC-001', name: 'Container User', category: 'process', severity: 'high' };
    expect(() => assertRedactionProvenance({ coverage: { suppressedFailures: [identityRow] } }, 'test-channel')).not.toThrow();
  });

  it('revokes the exemption the moment the same row grows passed + body text', () => {
    const grownRow = {
      checkId: 'PROC-001', name: 'Container User', category: 'process', severity: 'high',
      passed: false, message: 'now it carries bytes',
    };
    expect(() => assertRedactionProvenance({ coverage: { suppressedFailures: [grownRow] } }, 'test-channel')).toThrow(
      RedactionProvenanceError,
    );
  });

  // RED-PROOF: remove the `seen` cycle guard — this case hangs instead of
  // passing, and vitest's timeout turns it red.
  it('a cycle elsewhere in the payload does not stop the walk from reaching a launder', () => {
    const laundered = stripped(appliedFinding());
    const cyclic: Record<string, unknown> = { a: 1 };
    cyclic.self = cyclic;
    const payload = { first: cyclic, second: [laundered] };
    expect(() => assertRedactionProvenance(payload, 'test-channel')).toThrow(
      RedactionProvenanceError,
    );
  });
});

describe('redactOpenBagForPublish — the analyst advisory channel', () => {
  // RED-PROOF: make redactOpenBagForPublish return its input — both cases red.
  it('strips credential bytes from string leaves at any depth', () => {
    expect(GH.length, 'canary must clear the ghp_ 36-char pattern gate').toBe(4 + 36);
    const bag = {
      taskType: 'threatAnalysis',
      result: { analysis: `the token ${GH} is exposed`, nested: [{ note: `also ${GH}` }] },
      confidence: 0.9,
    };
    const out = redactOpenBagForPublish(bag) as typeof bag;
    const text = JSON.stringify(out);
    expect(text).not.toContain(GH);
    expect(text).toContain(GH_MARK);
    expect(out.confidence, 'non-string leaves must survive unchanged').toBe(0.9);
    expect(out.taskType).toBe('threatAnalysis');
  });

  it('control: a bag with no credential bytes passes through byte-identical', () => {
    const bag = { taskType: 'checkExplanation', result: { analysis: 'benign prose only' }, confidence: 0.5 };
    expect(redactOpenBagForPublish(bag)).toEqual(bag);
  });
});
