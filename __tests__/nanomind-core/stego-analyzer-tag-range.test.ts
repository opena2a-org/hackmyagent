import { describe, it, expect } from 'vitest';
import { analyzeSteganography } from '../../src/nanomind-core/analyzers/stego-analyzer';
import type { SecurityAST } from '../../src/nanomind-core/types';

/**
 * #959 — the NanoMind stego analyzer stopped its tag-character range at
 * U+E01EF, so a payload in U+E01F0-E01FF was never counted. The range now
 * reaches U+E01FF, matching the hardening scanner's UNICODE-STEGO checks.
 */
function astWithText(text: string): SecurityAST {
  return {
    artifactType: 'skill',
    contentHash: 'x',
    artifactPath: 'SKILL.md',
    artifactSize: text.length,
    declaredPurpose: '',
    evidenceSpans: [{ text }],
  } as unknown as SecurityAST;
}

describe('stego analyzer tag-character range', () => {
  it.each([0xE01F0, 0xE01F8, 0xE01FF])('counts U+%s as a tag character', (cp) => {
    const text = `Summarize the file.${String.fromCodePoint(cp)}`;
    const findings = analyzeSteganography(astWithText(text));
    const tag = findings.find(f => f.checkId === 'UNICODE-STEGO-004');
    expect(tag, `U+${cp.toString(16).toUpperCase()} not counted`).toBeDefined();
    expect(tag!.description).toBe('Found 1 tag character(s)');
  });

  it('counts every character across U+E01F0-E01FF', () => {
    let payload = '';
    for (let cp = 0xE01F0; cp <= 0xE01FF; cp++) payload += String.fromCodePoint(cp);
    const findings = analyzeSteganography(astWithText(`Hello${payload}`));
    const tag = findings.find(f => f.checkId === 'UNICODE-STEGO-004');
    expect(tag?.description).toBe('Found 16 tag character(s)');
  });

  it('does not count U+E0200, just past the range', () => {
    const findings = analyzeSteganography(astWithText(`Hello${String.fromCodePoint(0xE0200)}`));
    expect(findings.find(f => f.checkId === 'UNICODE-STEGO-004')).toBeUndefined();
  });
});
