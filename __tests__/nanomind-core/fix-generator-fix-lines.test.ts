/**
 * #367 — the fix generator carries its authored line structure out of band.
 *
 * `generateFix` composed multi-part fixes with `parts.join('\n')`, and the
 * renderer display-escaped the whole string, so every authored newline
 * reached the terminal as the two characters `\n`. The escape is right — a
 * newline inside a scanned file name must never split a report line (#324,
 * #334) — so the structure now travels beside the string as `fixLines`, one
 * element per authored part, and the renderer escapes each element on its own
 * line. The joined string is unchanged for every machine channel.
 *
 * Pinned here: a composed fix carries `fixLines` equal to its parts, with
 * `join('\n') === fix`; an analyzer-supplied fix passes through verbatim with
 * no structure claimed; and a hostile interpolated value stays INSIDE one
 * element — it never adds a line, because only `parts.push` adds a line.
 */
import { describe, it, expect } from 'vitest';
import { enrichFindings } from '../../src/nanomind-core/fix-generator';
import type { ASTFinding } from '../../src/nanomind-core/analyzers/capability-analyzer';
import type { SecurityAST } from '../../src/nanomind-core/types';
import { FIX_LINES } from '../../src/hardening/fix-lines';

const ast = (artifactPath = 'SKILL.md'): SecurityAST => ({
  artifactType: 'skill',
  contentHash: 'x'.repeat(64),
  artifactPath,
  artifactSize: 100,
  declaredPurpose: 'Summarise documents',
  declaredCapabilities: [],
  declaredConstraints: [],
  declaredDataAccess: [],
  inferredCapabilities: [],
  inferredRiskSurface: [],
  intentClassification: 'benign',
  intentConfidence: 0.9,
  dependsOn: [],
  governedBy: [],
  evidenceSpans: [],
  signature: '',
  modelVersion: 'test',
  compiledAt: '2026-01-01T00:00:00.000Z',
});

function finding(over: Partial<ASTFinding>): ASTFinding {
  return {
    checkId: 'AST-INJ-001',
    name: 'Prompt Injection Surface',
    description: 'd',
    category: 'injection',
    severity: 'critical',
    passed: false,
    message: 'processes external data with no injection constraint',
    fixable: false,
    file: 'SKILL.md',
    attackClass: 'PROMPT-INJECT',
    ...over,
  };
}

describe('#367 fix-generator carries authored line structure as fixLines', () => {
  it('a composed fix carries its parts, and the parts join to the string', () => {
    const [out] = enrichFindings([finding({})], ast());
    expect(out[FIX_LINES]).toBeDefined();
    expect(out[FIX_LINES]!.length).toBeGreaterThan(1);
    expect(out[FIX_LINES]!.join('\n')).toBe(out.fix);
  });

  it('no authored part is itself multi-line: every line boundary is a part boundary', () => {
    // A part carrying an authored newline would render as the two characters
    // `\n` on the text channel — the #367 symptom moved one level down.
    for (const attackClass of ['PROMPT-INJECT', 'CRED-HARDCODED', 'DATA-EXFIL', 'HEARTBEAT-RCE', 'PERSISTENCE', 'SOUL-BYPASS', 'SCAN-EVASION', 'SUPPLY-CHAIN', 'SCOPE-WILDCARD', 'PRIV-ESCALATION', 'CAPABILITY-CREEP', 'UNKNOWN-CLASS']) {
      const [out] = enrichFindings([finding({ attackClass, fix: undefined })], ast());
      expect(out[FIX_LINES], attackClass).toBeDefined();
      for (const part of out[FIX_LINES]!) expect(part, `${attackClass}: ${JSON.stringify(part)}`).not.toContain('\n');
    }
  });

  it('an analyzer-supplied fix passes through verbatim with no structure claimed', () => {
    const [out] = enrichFindings([finding({ attackClass: 'SOUL-GAP', fix: 'hackmyagent harden-soul . — add the missing domains' })], ast());
    expect(out.fix).toBe('hackmyagent harden-soul . — add the missing domains');
    expect(out[FIX_LINES]).toBeUndefined();
    // Absent, not present-and-undefined: no own symbol key on a verbatim fix.
    expect(Object.getOwnPropertySymbols(out)).not.toContain(FIX_LINES);
  });

  it('a hostile interpolated value stays inside one element and adds no line', () => {
    // The generic builder opens with `In ${file}: ${message}`, so the scanned
    // name is interpolated into a part verbatim — the shape #324 is about.
    const generic = { attackClass: 'UNKNOWN-CLASS', fix: undefined } as Partial<ASTFinding>;
    const clean = enrichFindings([finding(generic)], ast())[0];
    const hostile = enrichFindings([finding({ ...generic, file: 'evil\n  │ FORGED  line/SKILL.md' })], ast('evil\n  │ FORGED  line/SKILL.md'))[0];
    // Non-vacuity: the hostile value has to reach a part, or nothing is measured.
    expect(hostile.fix).toContain('FORGED');
    expect(hostile[FIX_LINES]!.length).toBe(clean[FIX_LINES]!.length);
    // The raw newline is inside an element; the renderer escapes it there.
    expect(hostile[FIX_LINES]!.some((p) => p.includes('\n'))).toBe(true);
    expect(hostile[FIX_LINES]!.join('\n')).toBe(hostile.fix);
  });

  it('guidance is untouched: still one string, still joined with spaces', () => {
    const [out] = enrichFindings([finding({})], ast());
    expect(typeof out.guidance).toBe('string');
    expect(out.guidance).not.toContain('\n');
  });
});
