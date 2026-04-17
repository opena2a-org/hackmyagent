import { describe, it, expect } from 'vitest';
import {
  isRenderableAnalystFinding,
  formatAnalystDescription,
  capAnalystThreatLevel,
  formatAnalystConfidence,
  LOW_CONFIDENCE_CAP,
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

describe('capAnalystThreatLevel', () => {
  it('caps CRITICAL to HIGH when confidence is below the calibration threshold', () => {
    // Real-world reproducer: NanoMind emits CRITICAL with hardcoded 60% confidence.
    const { level, capped } = capAnalystThreatLevel('CRITICAL', 0.60);
    expect(level).toBe('HIGH');
    expect(capped).toBe(true);
  });

  it('preserves CRITICAL when confidence meets the threshold', () => {
    const { level, capped } = capAnalystThreatLevel('CRITICAL', LOW_CONFIDENCE_CAP);
    expect(level).toBe('CRITICAL');
    expect(capped).toBe(false);
  });

  it('preserves CRITICAL when confidence is above the threshold', () => {
    const { level, capped } = capAnalystThreatLevel('CRITICAL', 0.95);
    expect(level).toBe('CRITICAL');
    expect(capped).toBe(false);
  });

  it('does not cap HIGH at any confidence (only CRITICAL is capped)', () => {
    for (const conf of [0.30, 0.60, 0.79, 0.85]) {
      const { level, capped } = capAnalystThreatLevel('HIGH', conf);
      expect(level).toBe('HIGH');
      expect(capped).toBe(false);
    }
  });

  it('does not cap MEDIUM or LOW at low confidence', () => {
    for (const lvl of ['MEDIUM', 'LOW', 'INFO']) {
      const { level, capped } = capAnalystThreatLevel(lvl, 0.40);
      expect(level).toBe(lvl);
      expect(capped).toBe(false);
    }
  });

  it('normalizes case and treats lowercase critical the same as uppercase', () => {
    const { level, capped } = capAnalystThreatLevel('critical', 0.60);
    expect(level).toBe('HIGH');
    expect(capped).toBe(true);
  });

  it('returns unknown when threatLevel is missing', () => {
    const { level, capped } = capAnalystThreatLevel(undefined, 0.95);
    expect(level).toBe('UNKNOWN');
    expect(capped).toBe(false);
  });
});

describe('formatAnalystConfidence', () => {
  it('shows numeric % when confidence meets the threshold', () => {
    const { label, numeric } = formatAnalystConfidence(0.85);
    expect(label).toBe('85%');
    expect(numeric).toBe(true);
  });

  it('shows numeric % at the threshold boundary (>= cap is numeric)', () => {
    const { label, numeric } = formatAnalystConfidence(LOW_CONFIDENCE_CAP);
    expect(label).toBe('80%');
    expect(numeric).toBe(true);
  });

  it('shows qualitative label when confidence is below the threshold', () => {
    // 60% is the hardcoded value the audit found on 14/14 findings.
    const { label, numeric } = formatAnalystConfidence(0.60);
    expect(label).toBe('low confidence');
    expect(numeric).toBe(false);
  });

  it('shows qualitative label just below the threshold', () => {
    const { label, numeric } = formatAnalystConfidence(0.79);
    expect(label).toBe('low confidence');
    expect(numeric).toBe(false);
  });

  it('rounds the numeric % rather than truncating', () => {
    const { label } = formatAnalystConfidence(0.876);
    expect(label).toBe('88%');
  });
});
