import { describe, it, expect } from 'vitest';
import {
  isRenderableAnalystFinding,
  formatAnalystDescription,
} from '../../src/output/analyst-render';

describe('isRenderableAnalystFinding', () => {
  it('drops below-confidence entries', () => {
    expect(isRenderableAnalystFinding({
      confidence: 0.4,
      taskType: 'threatAnalysis',
      result: { threatLevel: 'CRITICAL' },
    })).toBe(false);
  });

  it('drops threatAnalysis with NONE level (orphan-level bug)', () => {
    expect(isRenderableAnalystFinding({
      confidence: 0.9,
      taskType: 'threatAnalysis',
      result: { threatLevel: 'NONE' },
    })).toBe(false);
  });

  it('drops threatAnalysis with LOW and INFO levels', () => {
    for (const lvl of ['LOW', 'low', 'INFO', 'info']) {
      expect(isRenderableAnalystFinding({
        confidence: 0.9,
        taskType: 'threatAnalysis',
        result: { threatLevel: lvl },
      })).toBe(false);
    }
  });

  it('keeps CRITICAL, HIGH, MEDIUM threatAnalysis entries', () => {
    for (const lvl of ['CRITICAL', 'HIGH', 'MEDIUM']) {
      expect(isRenderableAnalystFinding({
        confidence: 0.9,
        taskType: 'threatAnalysis',
        result: { threatLevel: lvl },
      })).toBe(true);
    }
  });

  it('keeps non-threatAnalysis task types regardless of level', () => {
    expect(isRenderableAnalystFinding({
      confidence: 0.6,
      taskType: 'credentialContextClassification',
      result: { classification: 'test' },
    })).toBe(true);
    expect(isRenderableAnalystFinding({
      confidence: 0.6,
      taskType: 'intelReport',
      result: {},
    })).toBe(true);
  });
});

describe('formatAnalystDescription', () => {
  it('drops markdown header lines entirely (not just the #)', () => {
    const raw = '## Analysis\n\nThis artifact is a context-purpose mismatch attack.';
    const { text } = formatAnalystDescription(raw, { verbose: false });
    expect(text).toBe('This artifact is a context-purpose mismatch attack.');
    expect(text).not.toContain('Analysis');
    expect(text).not.toContain('##');
  });

  it('handles multiple header levels', () => {
    const raw = '# Title\n## Section\n### Subsection\n\nBody text here.';
    const { text } = formatAnalystDescription(raw, { verbose: false });
    expect(text).toBe('Body text here.');
  });

  it('collapses blank lines to an em-dash separator', () => {
    const raw = 'First paragraph.\n\nSecond paragraph.';
    const { text } = formatAnalystDescription(raw, { verbose: false });
    expect(text).toBe('First paragraph. — Second paragraph.');
  });

  it('collapses single newlines to spaces (wrapped prose)', () => {
    const raw = 'A long sentence\nthat wraps onto\nmultiple lines.';
    const { text } = formatAnalystDescription(raw, { verbose: false });
    expect(text).toBe('A long sentence that wraps onto multiple lines.');
  });

  it('strips bold markers', () => {
    const raw = 'This is **important** and **critical**.';
    const { text } = formatAnalystDescription(raw, { verbose: false });
    expect(text).toBe('This is important and critical.');
  });

  it('truncates at 240 chars with ellipsis when not verbose', () => {
    const raw = 'word '.repeat(100).trim(); // 499 chars
    const { text, truncated } = formatAnalystDescription(raw, { verbose: false });
    expect(truncated).toBe(true);
    expect(text.length).toBe(240);
    expect(text.endsWith('...')).toBe(true);
  });

  it('does not truncate when verbose', () => {
    const raw = 'word '.repeat(100).trim();
    const { text, truncated } = formatAnalystDescription(raw, { verbose: true });
    expect(truncated).toBe(false);
    expect(text).toBe(raw);
  });

  it('respects custom maxLen', () => {
    const raw = 'word '.repeat(20).trim();
    const { text, truncated } = formatAnalystDescription(raw, { verbose: false, maxLen: 30 });
    expect(truncated).toBe(true);
    expect(text.length).toBe(30);
  });

  it('real-world reproducer: header + description does not produce orphan "Analysis"', () => {
    // This is the exact shape the user hit on /tmp/hma-real-world/ibm-mcp/
    const raw = '## Analysis\n\nThis artifact is a context-purpose mismatch attack disguised as a legitimate agent configuration. The artifact contains a hidden malicious payload that redirects tool output to an attacker-controlled endpoint.';
    const { text, truncated } = formatAnalystDescription(raw, { verbose: false });
    expect(text.startsWith('This artifact')).toBe(true);
    expect(text).not.toMatch(/^Analysis/);
    // The full prose fits under 240; confirm no truncation.
    expect(truncated).toBe(false);
  });

  it('returns empty string when input is empty', () => {
    const { text, truncated } = formatAnalystDescription('', { verbose: false });
    expect(text).toBe('');
    expect(truncated).toBe(false);
  });

  it('returns empty string when input is only headers', () => {
    const { text } = formatAnalystDescription('## Header\n### Another\n', { verbose: false });
    expect(text).toBe('');
  });
});
