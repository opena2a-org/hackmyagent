/**
 * #552 — the stubs `expandSuppressed` hands back to the scorer and the gate
 * are finding-shaped: `checkId`, `severity`, `passed: false` and a `name`. The
 * publish-boundary reader recognises exactly that shape, so a stub with no
 * redaction provenance was one stray spread away from throwing a
 * `RedactionProvenanceError` on bytes that were never unsafe. They are emitted
 * through the boundary now, so they carry the stamp the reader asks for.
 *
 * RED-PROOF: revert `expandSuppressed` to build its stubs as bare literals and
 * the first three cases go red. The fourth is a mechanism control — it proves
 * the stub sits inside the predicate's range, so the green above is not
 * vacuous.
 */
import { describe, it, expect } from 'vitest';
import { expandSuppressed } from '../../src/ui/verdict-band';
import {
  assertRedactionProvenance,
  RedactionProvenanceError,
} from '../../src/hardening/finding-emit';

/** Synthesised at runtime — never a literal in the source tree. */
const GH = `ghp_${'a'.repeat(36)}`;

function row(over: Record<string, unknown> = {}) {
  return {
    checkId: 'CRED-001',
    name: 'Hardcoded credential',
    category: 'credentials',
    severity: 'high',
    count: 2,
    suppressedBy: 'ignore-flag',
    ...over,
  };
}

describe('expandSuppressed — stubs cross the redaction boundary (#552)', () => {
  it('every stub carries redaction provenance, so the publish reader passes them', () => {
    const stubs = expandSuppressed([row(), row({ checkId: 'GOV-001', category: 'governance', count: 1 })]);
    expect(stubs).toHaveLength(3);
    for (const s of stubs) {
      expect(['applied', 'clean']).toContain(s.redactionStatus);
      expect(Array.isArray(s.redactedShapes)).toBe(true);
    }
    expect(() => assertRedactionProvenance({ findings: stubs }, 'test-channel')).not.toThrow();
  });

  it('keeps the score inputs and adds nothing that carries finding text', () => {
    const [stub] = expandSuppressed([row({ count: 1 })]);
    expect(Object.keys(stub).sort()).toEqual([
      'category', 'checkId', 'name', 'passed', 'redactedShapes', 'redactionStatus', 'severity', 'suppressed',
    ]);
    expect(stub).toMatchObject({
      checkId: 'CRED-001',
      name: 'Hardcoded credential',
      category: 'credentials',
      severity: 'high',
      passed: false,
      suppressed: true,
      redactionStatus: 'clean',
      redactedShapes: [],
    });
  });

  it('runs the stub name through the redactor rather than trusting the row', () => {
    expect(GH.length, 'canary must clear the ghp_ 36-char pattern gate').toBe(4 + 36);
    const stubs = expandSuppressed([row({ name: `token ${GH}`, count: 2 })]);
    expect(stubs).toHaveLength(2);
    for (const s of stubs) {
      expect(s.redactionStatus).toBe('applied');
      expect(s.redactedShapes).toContain('github-pat');
    }
    expect(JSON.stringify(stubs)).not.toContain(GH);
  });

  it('control: a stub stripped of its stamp is finding-shaped and fires the reader', () => {
    const [stub] = expandSuppressed([row({ count: 1 })]);
    const { redactionStatus: _s, redactedShapes: _r, ...bare } = stub;
    expect(() => assertRedactionProvenance({ findings: [bare] }, 'test-channel')).toThrow(
      RedactionProvenanceError,
    );
  });
});
